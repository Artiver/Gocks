package forward

import (
	"net"
	"net/url"
	"testing"

	"gocks/internal/config"
	socks5proto "gocks/internal/protocol/socks5"
	"gocks/internal/testsupport"
)

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

func TestDialSocks5ProxyConnection(t *testing.T) {
	target := testsupport.TCPEcho(t)
	upstream := testsupport.Socks5Upstream(t, testsupport.Socks5Options{})

	conn, err := dialSingleHop(t, socks5Hop(t, upstream, "", ""), target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	testsupport.AssertEcho(t, conn, "no-auth")
}

func TestDialSocks5ProxyConnectionAuth(t *testing.T) {
	target := testsupport.TCPEcho(t)
	upstream := testsupport.Socks5Upstream(t, testsupport.Socks5Options{
		Cred: &socks5proto.Credential{Username: "user", Password: "pass"},
	})

	conn, err := dialSingleHop(t, socks5Hop(t, upstream, "user", "pass"), target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	testsupport.AssertEcho(t, conn, "with-auth")
}

func TestDialSocks5ProxyConnectionAuthFailure(t *testing.T) {
	target := testsupport.TCPEcho(t)
	upstream := testsupport.Socks5Upstream(t, testsupport.Socks5Options{
		Cred: &socks5proto.Credential{Username: "user", Password: "pass"},
	})

	if _, err := dialSingleHop(t, socks5Hop(t, upstream, "user", "wrong"), target); err == nil {
		t.Fatal("expected authentication failure")
	}
}

func TestDialSocks5ProxyConnectionReplyDomain(t *testing.T) {
	target := testsupport.TCPEcho(t)
	upstream := testsupport.Socks5Upstream(t, testsupport.Socks5Options{
		ReplyAddr: &socks5proto.Addr{Type: socks5proto.AddrDomain, Host: "bnd.example", Port: 1080},
	})

	conn, err := dialSingleHop(t, socks5Hop(t, upstream, "", ""), target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// A domain bound address is longer than 10 bytes; the tunnel must remain
	// clean (no trailing reply bytes).
	testsupport.AssertEcho(t, conn, "domain-reply")
}

func TestDialSocks5ProxyConnectionReplyIPv6(t *testing.T) {
	target := testsupport.TCPEcho(t)
	upstream := testsupport.Socks5Upstream(t, testsupport.Socks5Options{
		ReplyAddr: &socks5proto.Addr{Type: socks5proto.AddrIPv6, Host: "2001:db8::1", Port: 1080},
	})

	conn, err := dialSingleHop(t, socks5Hop(t, upstream, "", ""), target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	testsupport.AssertEcho(t, conn, "ipv6-reply")
}

func TestDialSocks5ProxyConnectionRefused(t *testing.T) {
	target := testsupport.TCPEcho(t)
	upstream := testsupport.Socks5Upstream(t, testsupport.Socks5Options{ReplyRep: socks5proto.RepConnRefused})

	if _, err := dialSingleHop(t, socks5Hop(t, upstream, "", ""), target); err == nil {
		t.Fatal("expected upstream refusal to be reported")
	}
}

func TestDialSocks5UDPAssociate(t *testing.T) {
	upstream := testsupport.Socks5Upstream(t, testsupport.Socks5Options{})

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
