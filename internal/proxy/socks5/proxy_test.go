package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"gocks/internal/config"
	socks5proto "gocks/internal/protocol/socks5"
	"gocks/internal/tunnel"
)

func setAuth(username, password string, enabled bool) {
	config.ProxyConfig.Username = username
	config.ProxyConfig.Password = password
	if enabled {
		config.ProxyConfig.Socks5Auth = []byte{0x01}
	} else {
		config.ProxyConfig.Socks5Auth = nil
	}
}

// runHandshake exercises socks5Handshake on one end of a net.Pipe while the
// client script drives the other end.
func runHandshake(t *testing.T, script func(net.Conn)) (string, error) {
	t.Helper()

	server, client := net.Pipe()
	defer client.Close()

	type result struct {
		id  string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		id, err := socks5Handshake(server)
		server.Close()
		ch <- result{id, err}
	}()

	script(client)

	select {
	case r := <-ch:
		return r.id, r.err
	case <-time.After(5 * time.Second):
		t.Fatal("socks5Handshake timed out")
		return "", nil
	}
}

func readMethodReply(t *testing.T, c net.Conn) byte {
	t.Helper()
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if reply[0] != 0x05 {
		t.Fatalf("unexpected version: %d", reply[0])
	}
	return reply[1]
}

func writeUserPass(t *testing.T, c net.Conn, username, password string) {
	t.Helper()
	req := []byte{0x01, byte(len(username))}
	req = append(req, username...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("write user/pass: %v", err)
	}
}

// startEcho starts a TCP echo server on loopback and returns its address.
func startEcho(t *testing.T) string {
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
				io.Copy(c, c)
			}(c)
		}
	}()

	return ln.Addr().String()
}

// startSocks5Proxy serves SOCKS5 on loopback and returns its address.
func startSocks5Proxy(t *testing.T) string {
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
			go HandleSocks5Connection(&c, nil)
		}
	}()

	return ln.Addr().String()
}

// dialSocks5Connect performs a no-auth handshake and a CONNECT to target,
// returning the established tunnel connection and the server reply.
func dialSocks5Connect(t *testing.T, proxyAddr, target string) (net.Conn, *socks5proto.Reply) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	if method := readMethodReply(t, conn); method != 0x00 {
		t.Fatalf("expected no-auth method, got %d", method)
	}

	addr, err := socks5proto.NewAddr(target)
	if err != nil {
		t.Fatal(err)
	}
	var req bytes.Buffer
	if err := socks5proto.NewRequest(socks5proto.CmdConnect, addr).Write(&req); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	reply, err := socks5proto.ReadReply(conn)
	if err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if reply.Rep != socks5proto.RepSucceeded {
		t.Fatalf("expected success reply, got rep=%d", reply.Rep)
	}
	return conn, reply
}

func TestHandshakeNoAuth(t *testing.T) {
	setAuth("", "", false)

	var method byte
	id, err := runHandshake(t, func(c net.Conn) {
		c.Write([]byte{0x05, 0x01, 0x00})
		method = readMethodReply(t, c)
	})

	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if id != "" {
		t.Fatalf("expected empty client ID, got %q", id)
	}
	if method != 0x00 {
		t.Fatalf("expected no-auth method, got %d", method)
	}
}

func TestHandshakeAuthSuccess(t *testing.T) {
	setAuth("user", "pass", true)

	var method, status byte
	id, err := runHandshake(t, func(c net.Conn) {
		c.Write([]byte{0x05, 0x02, 0x00, 0x02})
		method = readMethodReply(t, c)

		writeUserPass(t, c, "user", "pass")
		var resp [2]byte
		if _, e := io.ReadFull(c, resp[:]); e == nil {
			status = resp[1]
		}
	})

	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if id != "user" {
		t.Fatalf("expected client ID user, got %q", id)
	}
	if method != 0x02 {
		t.Fatalf("expected user/pass method, got %d", method)
	}
	if status != 0x00 {
		t.Fatalf("expected auth success status, got %d", status)
	}
}

func TestHandshakeAuthFailure(t *testing.T) {
	setAuth("user", "pass", true)

	var status byte
	_, err := runHandshake(t, func(c net.Conn) {
		c.Write([]byte{0x05, 0x01, 0x02})
		readMethodReply(t, c)

		writeUserPass(t, c, "user", "wrong")
		var resp [2]byte
		if _, e := io.ReadFull(c, resp[:]); e == nil {
			status = resp[1]
		}
	})

	if err == nil {
		t.Fatal("expected authentication failure")
	}
	if status != 0x01 {
		t.Fatalf("expected auth failure status, got %d", status)
	}
}

func TestHandshakeNoAcceptable(t *testing.T) {
	setAuth("user", "pass", true)

	var method byte
	_, err := runHandshake(t, func(c net.Conn) {
		c.Write([]byte{0x05, 0x01, 0x00}) // only offers no-auth
		method = readMethodReply(t, c)
	})

	if err == nil {
		t.Fatal("expected handshake failure")
	}
	if method != 0xFF {
		t.Fatalf("expected MethodNoAcceptable, got %d", method)
	}
}

func TestHandshakePreservesBufferedBytes(t *testing.T) {
	setAuth("", "", false)

	// Greeting immediately followed by a CONNECT request in the same read.
	reqWire := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90}
	prefix := append([]byte{0x05, 0x01, 0x00}, reqWire...)

	server, client := net.Pipe()
	defer client.Close()
	pc := tunnel.NewPrefixConn(prefix, server)

	go func() {
		var reply [2]byte
		io.ReadFull(client, reply[:])
	}()

	id, err := socks5Handshake(pc)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if id != "" {
		t.Fatalf("expected empty client ID, got %q", id)
	}

	got := make([]byte, len(reqWire))
	if _, err := io.ReadFull(pc, got); err != nil {
		t.Fatalf("read buffered request: %v", err)
	}
	if !bytes.Equal(got, reqWire) {
		t.Fatalf("buffered bytes lost: got %v want %v", got, reqWire)
	}
}

func TestSocks5ConnectEndToEnd(t *testing.T) {
	setAuth("", "", false)
	config.ForwardRequired = false

	echoAddr := startEcho(t)
	proxyAddr := startSocks5Proxy(t)

	conn, _ := dialSocks5Connect(t, proxyAddr, echoAddr)

	msg := []byte("ping-pong")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
}

// TestSocks5ConnectPipelinedPayload guards the exact-framing fix: a payload
// coalesced with the CONNECT request must survive the request parse.
func TestSocks5ConnectPipelinedPayload(t *testing.T) {
	setAuth("", "", false)
	config.ForwardRequired = false

	echoAddr := startEcho(t)
	proxyAddr := startSocks5Proxy(t)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	if method := readMethodReply(t, conn); method != 0x00 {
		t.Fatalf("expected no-auth method, got %d", method)
	}

	addr, err := socks5proto.NewAddr(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	var req bytes.Buffer
	if err := socks5proto.NewRequest(socks5proto.CmdConnect, addr).Write(&req); err != nil {
		t.Fatal(err)
	}

	payload := []byte("pipelined-payload")
	// Request and payload are written together so they may share a segment.
	if _, err := conn.Write(append(req.Bytes(), payload...)); err != nil {
		t.Fatal(err)
	}

	reply, err := socks5proto.ReadReply(conn)
	if err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if reply.Rep != socks5proto.RepSucceeded {
		t.Fatalf("expected success reply, got rep=%d", reply.Rep)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read pipelined payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("pipelined payload lost: got %q want %q", got, payload)
	}
}

func TestSocks5ConnectDomain(t *testing.T) {
	setAuth("", "", false)
	config.ForwardRequired = false

	echoAddr := startEcho(t)
	proxyAddr := startSocks5Proxy(t)

	_, port, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}

	conn, _ := dialSocks5Connect(t, proxyAddr, net.JoinHostPort("localhost", port))

	msg := []byte("domain-ok")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
}

func TestRequestUnsupportedCommand(t *testing.T) {
	setAuth("", "", false)

	server, client := net.Pipe()
	defer client.Close()

	repCh := make(chan byte, 1)
	go func() {
		// CMD=0x09 (invalid), ATYP=IPv4 1.2.3.4:80.
		client.Write([]byte{0x05, 0x09, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
		if reply, err := socks5proto.ReadReply(client); err == nil {
			repCh <- reply.Rep
		} else {
			repCh <- 0xFF
		}
	}()

	_ = socks5HandleRequest(&server)

	select {
	case rep := <-repCh:
		if rep != socks5proto.RepCmdUnsupported {
			t.Fatalf("expected RepCmdUnsupported, got %d", rep)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for reply")
	}
}

func TestRequestUnsupportedAddrType(t *testing.T) {
	setAuth("", "", false)

	server, client := net.Pipe()
	defer client.Close()

	repCh := make(chan byte, 1)
	go func() {
		// CMD=CONNECT, ATYP=0x09 (invalid).
		client.Write([]byte{0x05, 0x01, 0x00, 0x09})
		if reply, err := socks5proto.ReadReply(client); err == nil {
			repCh <- reply.Rep
		} else {
			repCh <- 0xFF
		}
	}()

	_ = socks5HandleRequest(&server)

	select {
	case rep := <-repCh:
		if rep != socks5proto.RepAddrUnsupported {
			t.Fatalf("expected RepAddrUnsupported, got %d", rep)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for reply")
	}
}

func TestConnectBndAddress(t *testing.T) {
	setAuth("", "", false)
	config.ForwardRequired = false

	echoAddr := startEcho(t)
	proxyAddr := startSocks5Proxy(t)

	_, reply := dialSocks5Connect(t, proxyAddr, echoAddr)

	if reply.Addr == nil {
		t.Fatal("missing bound address in reply")
	}
	if reply.Addr.Host != "127.0.0.1" {
		t.Fatalf("expected bound host 127.0.0.1, got %q", reply.Addr.Host)
	}
	if reply.Addr.Port == 0 {
		t.Fatal("expected non-zero bound port")
	}
	if reply.Addr.Type != socks5proto.AddrIPv4 {
		t.Fatalf("expected IPv4 bound address, got type %d", reply.Addr.Type)
	}
}

func TestConnectFailureRepCode(t *testing.T) {
	setAuth("", "", false)
	config.ForwardRequired = false

	// Reserve a port, then release it so nothing is listening on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	ln.Close()

	proxyAddr := startSocks5Proxy(t)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	if method := readMethodReply(t, conn); method != 0x00 {
		t.Fatalf("expected no-auth method, got %d", method)
	}

	addr, err := socks5proto.NewAddr(deadAddr)
	if err != nil {
		t.Fatal(err)
	}
	var req bytes.Buffer
	if err := socks5proto.NewRequest(socks5proto.CmdConnect, addr).Write(&req); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	reply, err := socks5proto.ReadReply(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply.Rep != socks5proto.RepConnRefused {
		t.Fatalf("expected RepConnRefused, got %d", reply.Rep)
	}
}

func TestMapDialErrorToRep(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want byte
	}{
		{"nil", nil, socks5proto.RepSucceeded},
		{"refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, socks5proto.RepConnRefused},
		{"host-unreachable", &net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}, socks5proto.RepHostUnreachable},
		{"net-unreachable", &net.OpError{Op: "dial", Err: syscall.ENETUNREACH}, socks5proto.RepNetUnreachable},
		{"timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, socks5proto.RepTTLExpired},
		{"text-refused", errors.New("dial tcp 127.0.0.1:1: connect: connection refused"), socks5proto.RepConnRefused},
		{"text-no-route", errors.New("dial tcp: no route to host"), socks5proto.RepHostUnreachable},
		{"other", errors.New("some dial failure"), socks5proto.RepFailure},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapDialErrorToRep(tc.err); got != tc.want {
				t.Fatalf("mapDialErrorToRep=%d want %d", got, tc.want)
			}
		})
	}
}
