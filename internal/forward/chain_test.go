package forward

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"gocks/internal/config"
	"gocks/internal/constant"
	socks5proto "gocks/internal/protocol/socks5"
	"gocks/internal/tunnel"
)

// targetLog records the CONNECT targets a relay double was asked to reach, in
// order, so a test can prove which hops were traversed.
type targetLog struct {
	mu      sync.Mutex
	targets []string
}

func (l *targetLog) add(target string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.targets = append(l.targets, target)
}

func (l *targetLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.targets...)
}

// startSocks5Relay runs a SOCKS5 server that really connects to the requested
// target, so it can act as any hop of a chain.
func startSocks5Relay(t *testing.T, cred *socks5proto.Credential) (string, *targetLog) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	log := &targetLog{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSocks5Relay(c, cred, log)
		}
	}()

	return ln.Addr().String(), log
}

func serveSocks5Relay(c net.Conn, cred *socks5proto.Credential, log *targetLog) {
	defer c.Close()

	selector := socks5proto.NewServerSelector()
	if cred != nil {
		selector = socks5proto.NewServerSelector(*cred)
	}
	if _, err := socks5proto.ServerHandshake(c, selector); err != nil {
		return
	}

	req, err := socks5proto.ReadRequest(c)
	if err != nil {
		return
	}
	if req.Cmd != socks5proto.CmdConnect || req.Addr == nil {
		socks5proto.NewReply(socks5proto.RepCmdUnsupported, nil).Write(c)
		return
	}

	target := req.Addr.String()
	log.add(target)

	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		socks5proto.NewReply(socks5proto.RepHostUnreachable, nil).Write(c)
		return
	}
	defer upstream.Close()

	reply := socks5proto.NewReply(socks5proto.RepSucceeded, nil)
	if bound, err := socks5proto.NewAddr(upstream.LocalAddr().String()); err == nil {
		reply.Addr = bound
	}
	if err := reply.Write(c); err != nil {
		return
	}
	relay(c, c, upstream)
}

// startHTTPRelay runs an HTTP CONNECT proxy that really connects to the
// requested target, so it can act as any hop of a chain.
func startHTTPRelay(t *testing.T, username, password string) (string, *targetLog) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	log := &targetLog{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveHTTPRelay(c, username, password, log)
		}
	}()

	return ln.Addr().String(), log
}

func serveHTTPRelay(c net.Conn, username, password string, log *targetLog) {
	defer c.Close()

	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != constant.ConnectMethod {
		c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	if username != "" || password != "" {
		want := constant.BasicAuthPrefix + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
		if req.Header.Get(constant.BasicAuthHeader) != want {
			c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"relay\"\r\nContent-Length: 0\r\n\r\n"))
			return
		}
	}

	target := req.Host
	log.add(target)

	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	defer upstream.Close()

	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Bytes buffered past the request headers already belong to the tunnel.
	var client io.Reader = c
	if n := br.Buffered(); n > 0 {
		prefix, err := br.Peek(n)
		if err != nil {
			return
		}
		client = tunnel.NewPrefixConn(prefix, c)
	}
	relay(client, c, upstream)
}

// relay copies bytes in both directions and returns once either side is done.
func relay(client io.Reader, clientConn io.Writer, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, client)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, upstream)
		done <- struct{}{}
	}()
	<-done
}

// httpHop builds one HTTP proxy hop through the real URL parser.
func httpHop(t *testing.T, bindAddr, username, password string) config.Url {
	t.Helper()

	raw := "http://" + bindAddr
	if username != "" || password != "" {
		raw = "http://" + url.QueryEscape(username) + ":" + url.QueryEscape(password) + "@" + bindAddr
	}

	var hop config.Url
	if err := config.ParseUrl(raw, &hop); err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return hop
}

// closedAddr returns a loopback address that nothing is listening on.
func closedAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// startSilentListener accepts connections, reads a byte and closes, so a
// handshake against it fails while the TCP connect itself succeeds.
func startSilentListener(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 2)
				c.Read(buf)
			}(c)
		}
	}()

	return ln.Addr().String()
}

func assertTargets(t *testing.T, log *targetLog, want ...string) {
	t.Helper()

	got := log.snapshot()
	if len(got) != len(want) {
		t.Fatalf("relay targets=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("relay target[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestDialThroughChainEmptyChain(t *testing.T) {
	if _, err := DialThroughChain(nil, startTCPEcho(t)); err == nil {
		t.Fatal("expected an empty chain to be rejected")
	}
}

func TestDialThroughChainTwoSocks5Hops(t *testing.T) {
	target := startTCPEcho(t)
	hop2, hop2Log := startSocks5Relay(t, nil)
	hop1, hop1Log := startSocks5Relay(t, nil)

	conn, err := DialThroughChain([]config.Url{
		socks5Hop(t, hop1, "", ""),
		socks5Hop(t, hop2, "", ""),
	}, target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, "two-hops")

	// The first hop reaches the second, and only the second sees the target.
	assertTargets(t, hop1Log, hop2)
	assertTargets(t, hop2Log, target)
}

func TestDialThroughChainThreeHops(t *testing.T) {
	target := startTCPEcho(t)
	hop3, hop3Log := startSocks5Relay(t, nil)
	hop2, hop2Log := startSocks5Relay(t, nil)
	hop1, hop1Log := startSocks5Relay(t, nil)

	conn, err := DialThroughChain([]config.Url{
		socks5Hop(t, hop1, "", ""),
		socks5Hop(t, hop2, "", ""),
		socks5Hop(t, hop3, "", ""),
	}, target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, "three-hops")

	assertTargets(t, hop1Log, hop2)
	assertTargets(t, hop2Log, hop3)
	assertTargets(t, hop3Log, target)
}

func TestDialThroughChainSocks5ThenHTTP(t *testing.T) {
	target := startTCPEcho(t)
	proxy2, proxy2Log := startHTTPRelay(t, "", "")
	proxy1, proxy1Log := startSocks5Relay(t, nil)

	conn, err := DialThroughChain([]config.Url{
		socks5Hop(t, proxy1, "", ""),
		httpHop(t, proxy2, "", ""),
	}, target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, "socks5-then-http")

	assertTargets(t, proxy1Log, proxy2)
	assertTargets(t, proxy2Log, target)
}

func TestDialThroughChainHTTPThenSocks5(t *testing.T) {
	target := startTCPEcho(t)
	proxy2, proxy2Log := startSocks5Relay(t, nil)
	proxy1, proxy1Log := startHTTPRelay(t, "", "")

	conn, err := DialThroughChain([]config.Url{
		httpHop(t, proxy1, "", ""),
		socks5Hop(t, proxy2, "", ""),
	}, target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, "http-then-socks5")

	assertTargets(t, proxy1Log, proxy2)
	assertTargets(t, proxy2Log, target)
}

func TestDialThroughChainSingleHTTPHop(t *testing.T) {
	target := startTCPEcho(t)
	proxy, proxyLog := startHTTPRelay(t, "", "")

	conn, err := DialThroughChain([]config.Url{httpHop(t, proxy, "", "")}, target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, "single-http-hop")
	assertTargets(t, proxyLog, target)
}

func TestDialThroughChainSingleHTTPHopAuth(t *testing.T) {
	target := startTCPEcho(t)
	proxy, proxyLog := startHTTPRelay(t, "user", "pass")

	conn, err := DialThroughChain([]config.Url{httpHop(t, proxy, "user", "pass")}, target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, "http-auth")
	assertTargets(t, proxyLog, target)
}

func TestDialThroughChainHTTPHopAuthFailure(t *testing.T) {
	target := startTCPEcho(t)
	proxy, proxyLog := startHTTPRelay(t, "user", "pass")

	_, err := DialThroughChain([]config.Url{httpHop(t, proxy, "user", "wrong")}, target)
	if err == nil {
		t.Fatal("expected the proxy to reject the credentials")
	}
	if !strings.Contains(err.Error(), "hop[0]") {
		t.Fatalf("error should name the failing hop, got: %v", err)
	}
	assertTargets(t, proxyLog)
}

// TestDialThroughChainPerHopCredentials proves every hop uses its own
// credentials: the first hop accepts, the second rejects the first hop's pair.
func TestDialThroughChainPerHopCredentials(t *testing.T) {
	target := startTCPEcho(t)
	hop2, hop2Log := startSocks5Relay(t, &socks5proto.Credential{Username: "user2", Password: "pass2"})
	hop1, hop1Log := startSocks5Relay(t, &socks5proto.Credential{Username: "user1", Password: "pass1"})

	_, err := DialThroughChain([]config.Url{
		socks5Hop(t, hop1, "user1", "pass1"),
		socks5Hop(t, hop2, "user1", "pass1"),
	}, target)
	if err == nil {
		t.Fatal("expected the second hop to reject the first hop's credentials")
	}
	if !strings.Contains(err.Error(), "hop[1]") {
		t.Fatalf("error should name the failing hop, got: %v", err)
	}
	// The first hop accepted our credentials and was asked to reach the second.
	assertTargets(t, hop1Log, hop2)
	assertTargets(t, hop2Log)

	// With each hop's own credentials the same chain works.
	conn, err := DialThroughChain([]config.Url{
		socks5Hop(t, hop1, "user1", "pass1"),
		socks5Hop(t, hop2, "user2", "pass2"),
	}, target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, "per-hop-credentials")
	assertTargets(t, hop2Log, target)
}

// TestDialThroughChainUnreachableNextHop covers the case where an intermediate
// hop cannot reach the following one: the report comes from the hop that was
// being talked to, so the error names that hop.
func TestDialThroughChainUnreachableNextHop(t *testing.T) {
	target := startTCPEcho(t)
	hop1, hop1Log := startSocks5Relay(t, nil)
	unreachable := closedAddr(t)

	_, err := DialThroughChain([]config.Url{
		socks5Hop(t, hop1, "", ""),
		socks5Hop(t, unreachable, "", ""),
	}, target)
	if err == nil {
		t.Fatal("expected the unreachable hop to fail the dial")
	}
	if !strings.Contains(err.Error(), "hop[0]") {
		t.Fatalf("error should name the hop that reported it, got: %v", err)
	}
	// The first hop accepted our credentials and was asked to reach the second.
	assertTargets(t, hop1Log, unreachable)
}

// TestDialThroughChainReportsFailingHop covers a failure inside a deeper hop's
// own handshake, which must be attributed to that hop.
func TestDialThroughChainReportsFailingHop(t *testing.T) {
	target := startTCPEcho(t)
	hop2 := startSilentListener(t)
	hop1, hop1Log := startSocks5Relay(t, nil)

	_, err := DialThroughChain([]config.Url{
		socks5Hop(t, hop1, "", ""),
		socks5Hop(t, hop2, "", ""),
	}, target)
	if err == nil {
		t.Fatal("expected the silent hop to fail the handshake")
	}
	if !strings.Contains(err.Error(), "hop[1]") || !strings.Contains(err.Error(), hop2) {
		t.Fatalf("error should name the failing hop and address, got: %v", err)
	}
	assertTargets(t, hop1Log, hop2)
}

func TestDialThroughChainRejectsUnknownScheme(t *testing.T) {
	target := startTCPEcho(t)
	_, err := DialThroughChain([]config.Url{{Scheme: "ftp", BindAddr: "127.0.0.1:1"}}, target)
	if err == nil {
		t.Fatal("expected an unsupported scheme to be rejected")
	}
	if !strings.Contains(err.Error(), "hop[0]") {
		t.Fatalf("error should name the failing hop, got: %v", err)
	}
}
