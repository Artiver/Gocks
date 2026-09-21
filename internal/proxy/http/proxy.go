package http

import (
	"bufio"
	"errors"
	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/dialer"
	"gocks/internal/tunnel"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func Run() {
	listen, err := net.Listen("tcp", config.ProxyConfig.BindAddr)
	if err != nil {
		log.Fatalln("Error listening:", err)
	}
	defer func(listen net.Listener) {
		err = listen.Close()
		if err != nil {
			log.Println("listening close error", err)
		}
	}(listen)

	log.Println("HTTP proxy listening", config.ProxyConfig.BindAddr)

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}

		go HandleHTTPConnection(&conn, nil)
	}
}

func HandleHTTPConnection(conn *net.Conn, firstBuff []byte) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	if conn == nil {
		return
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Println("connection close error", err)
		}
	}(*conn)

	var reader io.Reader = *conn
	if firstBuff != nil {
		reader = tunnel.NewPrefixConn(firstBuff, *conn)
	}
	br := bufio.NewReader(reader)

	for {
		close, err := handleOneRequest(br, *conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				log.Println("[HTTP]", err)
			}
			return
		}
		if close {
			return
		}
	}
}

func handleOneRequest(br *bufio.Reader, conn net.Conn) (bool, error) {
	if err := conn.SetReadDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return true, err
	}

	req, err := http.ReadRequest(br)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
			return true, nil
		}
		return true, err
	}
	defer req.Body.Close()

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return true, err
	}

	if config.ProxyConfig.Socks5Auth != nil {
		if !checkProxyAuthorizationFromHeader(req.Header) {
			_, err := conn.Write(config.AuthRequiredResponse)
			if err != nil {
				log.Println("send 407 error:", err)
			}
			return true, nil
		}
	}

	if req.Method == constant.ConnectMethod {
		return handleConnectMethod(conn, br, req)
	}
	return handleProxyMethod(conn, req)
}

func handleConnectMethod(conn net.Conn, br *bufio.Reader, req *http.Request) (bool, error) {
	addr := req.Host
	if addr == "" && req.URL != nil {
		addr = req.URL.Host
	}
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	server, err := dialer.DialTcpConnection(addr)
	if err != nil {
		log.Println(err)
		conn.Write(config.BadGatewayResponse)
		return true, err
	}
	defer server.Close()

	clientAddr := conn.RemoteAddr().String()
	log.Printf("[HTTP] %s <--> %s", clientAddr, addr)

	if _, err = conn.Write(config.ConnectedResponse); err != nil {
		return true, err
	}

	var wrappedConn net.Conn = tunnel.NewReaderConn(br, conn)
	err = tunnel.TransportData(&server, &wrappedConn)
	if err != nil {
		log.Println("[HTTP]", err)
	}
	return true, nil
}

func handleProxyMethod(conn net.Conn, req *http.Request) (bool, error) {
	addr := req.Host
	if addr == "" && req.URL != nil {
		addr = req.URL.Host
	}
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}

	server, err := dialer.DialTcpConnection(addr)
	if err != nil {
		log.Println(err)
		conn.Write(config.BadGatewayResponse)
		return true, err
	}
	defer server.Close()

	clientAddr := conn.RemoteAddr().String()
	log.Printf("[HTTP] %s <--> %s", clientAddr, addr)

	req.Header.Del(constant.BasicAuthHeader)
	req.Header.Del(constant.ProxyConnectKey)
	req.Header.Add(constant.ViaHeader, constant.ViaValue)

	if req.URL.IsAbs() {
		req.URL.Scheme = ""
		req.URL.Host = ""
		req.RequestURI = req.URL.RequestURI()
	}

	if err := req.Write(server); err != nil {
		return true, err
	}

	serverBr := bufio.NewReader(server)
	resp, err := http.ReadResponse(serverBr, req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()

	resp.Header.Add(constant.ViaHeader, constant.ViaValue)

	close := shouldCloseConnection(req, resp)

	if err := resp.Write(conn); err != nil {
		return true, err
	}

	return close, nil
}

func shouldCloseConnection(req *http.Request, resp *http.Response) bool {
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		return !strings.EqualFold(req.Header.Get("Connection"), "keep-alive")
	}
	if strings.EqualFold(req.Header.Get("Connection"), "close") {
		return true
	}
	if resp.Close {
		return true
	}
	return false
}
