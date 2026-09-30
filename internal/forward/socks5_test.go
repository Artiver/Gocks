package forward

import (
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"gocks/internal/config"
	socks5proto "gocks/internal/protocol/socks5"
)

func startTCPEcho(t *testing.T) string {
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

type upstreamOptions struct {
	cred      *socks5proto.Credential
	replyRep  byte
	replyAddr *socks5proto.Addr
}

func startSocks5Upstream(t *testing.T, opts upstreamOptions) string {
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
			go serveUpstream(c, opts)
		}
	}()

	return ln.Addr().String()
}

// serveUpstream is a codec-based SOCKS5 server used as a test double.
func serveUpstream(c net.Conn, opts upstreamOptions) {
	defer c.Close()

	selector := socks5proto.NewServerSelector()
	if opts.cred != nil {
		selector = socks5proto.NewServerSelector(*opts.cred)
	}
	if _, err := socks5proto.ServerHandshake(c, selector); err != nil {
		return
	}

	req, err := socks5proto.ReadRequest(c)
	if err != nil {
		return
	}

	if opts.replyRep != socks5proto.RepSucceeded {
		socks5proto.NewReply(opts.replyRep, nil).Write(c)
		return
	}

	if req.Cmd == socks5proto.CmdUDP {
		socks5proto.NewReply(socks5proto.RepSucceeded, &socks5proto.Addr{
			Type: socks5proto.AddrIPv4, Host: "127.0.0.1", Port: 12345,
		}).Write(c)
		io.Copy(io.Discard, c) // keep the association alive
		return
	}

	socks5proto.NewReply(socks5proto.RepSucceeded, opts.replyAddr).Write(c)
	io.Copy(c, c) // echo whatever the client tunnels
}

// socks5Hop builds one chain hop through the real URL parser, so credentials
// and auth headers match what the command line produces.
func socks5Hop(t *testing.T, bindAddr, username, password string) config.Url {
	t.Helper()

	raw := "socks5://" + bindAddr
	if username != "" || password != "" {
		raw = "socks5://" + url.QueryEscape(username) + ":" + url.QueryEscape(password) + "@" + bindAddr
	}

	var hop config.Url
	if err := config.ParseUrl(raw, &hop); err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return hop
}

// dialSingleHop is the classic one-level -F case expressed as a chain.
func dialSingleHop(t *testing.T, hop config.Url, target string) (net.Conn, error) {
	t.Helper()
	return DialThroughChain([]config.Url{hop}, target)
}

func assertEcho(t *testing.T, conn net.Conn, msg string) {
	t.Helper()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("echo=%q want %q", got, msg)
	}
}

func TestDialSocks5ProxyConnection(t *testing.T) {
	target := startTCPEcho(t)
	upstream := startSocks5Upstream(t, upstreamOptions{})

	conn, err := dialSingleHop(t, socks5Hop(t, upstream, "", ""), target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, "no-auth")
}

func TestDialSocks5ProxyConnectionAuth(t *testing.T) {
	target := startTCPEcho(t)
	upstream := startSocks5Upstream(t, upstreamOptions{
		cred: &socks5proto.Credential{Username: "user", Password: "pass"},
	})

	conn, err := dialSingleHop(t, socks5Hop(t, upstream, "user", "pass"), target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, "with-auth")
}

func TestDialSocks5ProxyConnectionAuthFailure(t *testing.T) {
	target := startTCPEcho(t)
	upstream := startSocks5Upstream(t, upstreamOptions{
		cred: &socks5proto.Credential{Username: "user", Password: "pass"},
	})

	if _, err := dialSingleHop(t, socks5Hop(t, upstream, "user", "wrong"), target); err == nil {
		t.Fatal("expected authentication failure")
	}
}

func TestDialSocks5ProxyConnectionReplyDomain(t *testing.T) {
	target := startTCPEcho(t)
	upstream := startSocks5Upstream(t, upstreamOptions{
		replyAddr: &socks5proto.Addr{Type: socks5proto.AddrDomain, Host: "bnd.example", Port: 1080},
	})

	conn, err := dialSingleHop(t, socks5Hop(t, upstream, "", ""), target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// A domain bound address is longer than 10 bytes; the tunnel must remain
	// clean (no trailing reply bytes).
	assertEcho(t, conn, "domain-reply")
}

func TestDialSocks5ProxyConnectionReplyIPv6(t *testing.T) {
	target := startTCPEcho(t)
	upstream := startSocks5Upstream(t, upstreamOptions{
		replyAddr: &socks5proto.Addr{Type: socks5proto.AddrIPv6, Host: "2001:db8::1", Port: 1080},
	})

	conn, err := dialSingleHop(t, socks5Hop(t, upstream, "", ""), target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, "ipv6-reply")
}

func TestDialSocks5ProxyConnectionRefused(t *testing.T) {
	target := startTCPEcho(t)
	upstream := startSocks5Upstream(t, upstreamOptions{replyRep: socks5proto.RepConnRefused})

	if _, err := dialSingleHop(t, socks5Hop(t, upstream, "", ""), target); err == nil {
		t.Fatal("expected upstream refusal to be reported")
	}
}

func TestDialSocks5UDPAssociate(t *testing.T) {
	upstream := startSocks5Upstream(t, upstreamOptions{})

	ctrl, relay, err := DialSocks5UDPAssociate(socks5Hop(t, upstream, "", ""))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ctrl.Close()

	if relay == nil {
		t.Fatal("missing relay address")
	}
	if relay.Host != "127.0.0.1" || relay.Port != 12345 {
		t.Fatalf("relay=%s want 127.0.0.1:12345", relay)
	}
}
