package socks5

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"gocks/internal/config"
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

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	go func() {
		for {
			c, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go HandleSocks5Connection(&c, nil)
		}
	}()

	conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Method negotiation.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	if method := readMethodReply(t, conn); method != 0x00 {
		t.Fatalf("expected no-auth method, got %d", method)
	}

	// CONNECT to the echo server.
	target := echoLn.Addr().(*net.TCPAddr)
	ip := target.IP.To4()
	req := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(target.Port >> 8), byte(target.Port)}
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("expected success reply, got rep=%d", resp[1])
	}

	// Round-trip a payload through the tunnel.
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
