package socks5

import (
	"gocks/internal/config"
	socks5proto "gocks/internal/protocol/socks5"
	"io"
	"net"
	"testing"
	"time"
)

func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
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

func startSocks5Server(t *testing.T, p *Proxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.HandleConnection(c, nil)
		}
	}()
	return ln.Addr().String()
}

func TestHandleSocks5Connect(t *testing.T) {
	p := New(config.Config{})
	target := startEchoServer(t)
	proxyAddr := startSocks5Server(t, p)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	if _, err := conn.Write([]byte{socks5proto.Version, 1, socks5proto.MethodNoAuth}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	var selected [2]byte
	if _, err := io.ReadFull(conn, selected[:]); err != nil {
		t.Fatalf("read method: %v", err)
	}
	if selected[0] != socks5proto.Version || selected[1] != socks5proto.MethodNoAuth {
		t.Fatalf("method selection = %v, want [5 0]", selected)
	}

	addr, err := socks5proto.NewAddr(target)
	if err != nil {
		t.Fatalf("NewAddr: %v", err)
	}
	if err := socks5proto.NewRequest(socks5proto.CmdConnect, addr).Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply, err := socks5proto.ReadReply(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply.Rep != socks5proto.RepSucceeded {
		t.Fatalf("reply = %s, want succeeded", socks5proto.ReprString(reply.Rep))
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q, want %q", buf, "ping")
	}
}

func TestHandleSocks5RejectsNoAuthWhenCredentialsConfigured(t *testing.T) {
	p := New(config.Config{Listen: config.Endpoint{
		Auth: &config.Auth{Username: "user", Password: "pass"},
	}})
	proxyAddr := startSocks5Server(t, p)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	if _, err := conn.Write([]byte{socks5proto.Version, 1, socks5proto.MethodNoAuth}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	var selected [2]byte
	if _, err := io.ReadFull(conn, selected[:]); err != nil {
		t.Fatalf("read method: %v", err)
	}
	if selected[0] != socks5proto.Version || selected[1] != socks5proto.MethodNoAcceptable {
		t.Errorf("method selection = %v, want [5 255]", selected)
	}
}
