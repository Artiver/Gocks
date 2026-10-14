package http

import (
	"bufio"
	"context"
	"errors"
	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/dialer"
	"gocks/internal/server"
	"gocks/internal/tunnel"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Run serves HTTP proxying until ctx is cancelled.
func Run(ctx context.Context) error {
	return server.Serve(ctx, "HTTP proxy", config.ProxyConfig.BindAddr, func(conn net.Conn) {
		HandleHTTPConnection(conn, nil)
	})
}

// HandleHTTPConnection serves one client, reusing the connection for further
// requests unless the request or the response says otherwise. firstBuff carries
// the bytes the mixed-mode dispatcher pre-read to tell HTTP and SOCKS5 apart.
func HandleHTTPConnection(conn net.Conn, firstBuff []byte) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	defer func() {
		if err := conn.Close(); err != nil {
			log.Println("connection close error", err)
		}
	}()

	var reader io.Reader = conn
	if len(firstBuff) > 0 {
		reader = tunnel.NewPrefixConn(firstBuff, conn)
	}
	br := bufio.NewReader(reader)

	for {
		shouldClose, err := handleOneRequest(br, conn)
		if err != nil {
			if !isClientGone(err) {
				log.Println("[HTTP]", err)
			}
			return
		}
		if shouldClose {
			return
		}
	}
}

// isClientGone reports whether err is just the client closing the connection
// rather than a proxying failure.
func isClientGone(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed)
}

func handleOneRequest(br *bufio.Reader, conn net.Conn) (bool, error) {
	if err := conn.SetReadDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return true, err
	}

	req, err := http.ReadRequest(br)
	if err != nil {
		return true, err
	}
	defer req.Body.Close()

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return true, err
	}

	if auth := config.ProxyConfig.Auth; auth != nil && !checkProxyAuthorizationFromHeader(auth, req.Header) {
		if _, err := conn.Write(config.AuthRequiredResponse); err != nil {
			log.Println("send 407 error:", err)
		}
		return true, nil
	}

	if req.Method == constant.ConnectMethod {
		return handleConnectMethod(conn, br, req)
	}
	return handleProxyMethod(conn, req)
}

// dialTarget resolves the target of req, defaulting to defaultPort when the
// request carries no port, and connects to it. It answers 502 on failure.
func dialTarget(conn net.Conn, req *http.Request, defaultPort string) (net.Conn, string, error) {
	addr := targetAddr(req, strings.TrimPrefix(defaultPort, ":"))

	upstream, err := dialer.DialTcpConnection(addr)
	if err != nil {
		log.Println(err)
		if _, werr := conn.Write(config.BadGatewayResponse); werr != nil {
			log.Println("send 502 error:", werr)
		}
		return nil, addr, err
	}

	log.Printf("[HTTP] %s <--> %s", conn.RemoteAddr(), addr)
	return upstream, addr, nil
}

// targetAddr resolves the host:port to dial for req, defaulting to defaultPort
// when the request carries no port. SplitHostPort is the reliable "carries a
// port" check: a bare IPv6 literal contains ':' but no port, and JoinHostPort
// brackets a bare IPv6 host correctly.
func targetAddr(req *http.Request, defaultPort string) string {
	addr := req.Host
	if addr == "" && req.URL != nil {
		addr = req.URL.Host
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), defaultPort)
	}
	return addr
}

func handleConnectMethod(conn net.Conn, br *bufio.Reader, req *http.Request) (bool, error) {
	upstream, addr, err := dialTarget(conn, req, ":443")
	if err != nil {
		return true, err
	}
	defer upstream.Close()

	if _, err := conn.Write(config.ConnectedResponse); err != nil {
		return true, err
	}

	// Replay anything the client sent after CONNECT before tunnelling.
	start := time.Now()
	stats, err := tunnel.TransportDataStats(upstream, tunnel.NewReaderConn(br, conn))
	log.Printf("[HTTP] [CONNECT] %s <-> %s closed after %s (%d bytes sent, %d bytes received)",
		conn.RemoteAddr(), addr, time.Since(start).Round(time.Millisecond), stats.SourceToTarget, stats.TargetToSource)
	if err != nil {
		log.Println("[HTTP]", err)
	}
	return true, nil
}

func handleProxyMethod(conn net.Conn, req *http.Request) (bool, error) {
	upstream, addr, err := dialTarget(conn, req, ":80")
	if err != nil {
		return true, err
	}
	defer upstream.Close()

	req.Header.Del(constant.BasicAuthHeader)
	req.Header.Del(constant.ProxyConnectKey)
	req.Header.Add(constant.ViaHeader, constant.ViaValue)

	if req.URL.IsAbs() {
		req.URL.Scheme = ""
		req.URL.Host = ""
		req.RequestURI = req.URL.RequestURI()
	}

	start := time.Now()
	reqOut := &countingWriter{w: upstream}
	if err := req.Write(reqOut); err != nil {
		return true, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()

	resp.Header.Add(constant.ViaHeader, constant.ViaValue)

	shouldClose := finishResponse(req, resp)
	respOut := &countingWriter{w: conn}
	err = resp.Write(respOut)
	log.Printf("[HTTP] [PROXY] %s <-> %s %s in %s (%d bytes sent, %d bytes received)",
		conn.RemoteAddr(), addr, req.URL, time.Since(start).Round(time.Millisecond), reqOut.n, respOut.n)
	if err != nil {
		return true, err
	}
	return shouldClose, nil
}

// countingWriter counts the bytes written through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// finishResponse adjusts the upstream response for the client and reports
// whether the client connection must be closed afterwards.
//
// Chunked is an HTTP/1.1 transfer coding; rather than buffering the whole
// body to re-encode it, the framing is dropped for an HTTP/1.0 client and
// Response.Write streams the decoded body raw instead.
//
// A body whose length cannot be known up front (no Content-Length, no chunked
// framing) is delimited only by the end of the connection. The client must see
// the connection close or it waits for more bytes forever, so keep-alive
// cannot continue.
func finishResponse(req *http.Request, resp *http.Response) bool {
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		resp.TransferEncoding = nil
	}
	shouldClose := shouldCloseConnection(req, resp)
	if resp.ContentLength < 0 && len(resp.TransferEncoding) == 0 {
		shouldClose = true
	}
	return shouldClose
}

func shouldCloseConnection(req *http.Request, resp *http.Response) bool {
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		return !strings.EqualFold(req.Header.Get("Connection"), "keep-alive")
	}
	if strings.EqualFold(req.Header.Get("Connection"), "close") {
		return true
	}
	return resp.Close
}
