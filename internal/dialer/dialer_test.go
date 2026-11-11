package dialer

import (
	"bufio"
	"gocks/internal/config"
	"gocks/internal/constant"
	socks5proto "gocks/internal/protocol/socks5"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func withForwardChain(t *testing.T, chain []config.Url) {
	t.Helper()
	old := config.ForwardChain
	config.ForwardChain = chain
	t.Cleanup(func() { config.ForwardChain = old })
}

// fakeHTTPProxy accepts one connection and answers connects CONNECT requests
// on it, reporting the target of each request.
func fakeHTTPProxy(t *testing.T, connects int) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	hosts := make(chan string, connects)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for i := 0; i < connects; i++ {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					hosts <- req.Host
					if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
						return
					}
				}
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln.Addr().String(), hosts
}

// fakeSocks5Proxy accepts one connection and serves the SOCKS5 client
// handshake, optionally requiring cred. It reports the target of each request
// and answers UDP ASSOCIATE with relay.
func fakeSocks5Proxy(t *testing.T, cred *socks5proto.Credential, relay *socks5proto.Addr) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	targets := make(chan string, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()

				methods, err := socks5proto.ReadMethods(c)
				if err != nil {
					return
				}
				method := socks5proto.MethodNoAuth
				if cred != nil {
					if !socks5proto.HasMethod(methods, socks5proto.MethodUserPass) {
						socks5proto.WriteMethod(socks5proto.MethodNoAcceptable, c)
						return
					}
					method = socks5proto.MethodUserPass
				}
				if err := socks5proto.WriteMethod(method, c); err != nil {
					return
				}

				if method == socks5proto.MethodUserPass {
					req, err := socks5proto.ReadUserPassRequest(c)
					if err != nil {
						return
					}
					status := socks5proto.UserPassSuccess
					if req.Username != cred.Username || req.Password != cred.Password {
						status = socks5proto.UserPassFailure
					}
					socks5proto.NewUserPassResponse(socks5proto.UserPassVersion, status).Write(c)
					if status != socks5proto.UserPassSuccess {
						return
					}
				}

				req, err := socks5proto.ReadRequest(c)
				if err != nil {
					return
				}
				targets <- req.Addr.String()

				bound := &socks5proto.Addr{Type: socks5proto.AddrIPv4, Host: "0.0.0.0"}
				if req.Cmd == socks5proto.CmdUDP && relay != nil {
					bound = relay
				}
				if err := socks5proto.NewReply(socks5proto.RepSucceeded, bound).Write(c); err != nil {
					return
				}
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln.Addr().String(), targets
}

// acceptOnce starts a listener that accepts and holds one connection, used as
// a reachable first hop when the hop itself is expected to be rejected.
func acceptOnce(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c)
	}()
	return ln.Addr().String()
}

func TestDialTcpConnectionDirect(t *testing.T) {
	withForwardChain(t, nil)
	addr := acceptOnce(t)

	conn, err := DialTcpConnection(addr)
	if err != nil {
		t.Fatalf("DialTcpConnection: %v", err)
	}
	conn.Close()
}

func TestDialThroughChainHTTP(t *testing.T) {
	proxyAddr, hosts := fakeHTTPProxy(t, 2)
	chain := []config.Url{
		{Scheme: constant.HTTP, BindAddr: proxyAddr},
		{Scheme: constant.HTTP, BindAddr: "hop2.example:8080"},
	}

	conn, err := DialThroughChain(chain, "target.example:443")
	if err != nil {
		t.Fatalf("DialThroughChain: %v", err)
	}
	defer conn.Close()

	if got := <-hosts; got != "hop2.example:8080" {
		t.Errorf("first CONNECT target = %q, want %q", got, "hop2.example:8080")
	}
	if got := <-hosts; got != "target.example:443" {
		t.Errorf("second CONNECT target = %q, want %q", got, "target.example:443")
	}
}

func TestDialThroughChainSocks5(t *testing.T) {
	proxyAddr, targets := fakeSocks5Proxy(t, nil, nil)

	conn, err := DialThroughChain([]config.Url{
		{Scheme: constant.Socks5, BindAddr: proxyAddr},
	}, "target.example:443")
	if err != nil {
		t.Fatalf("DialThroughChain: %v", err)
	}
	defer conn.Close()

	if got := <-targets; got != "target.example:443" {
		t.Errorf("request target = %q, want %q", got, "target.example:443")
	}
}

func TestDialThroughChainSocks5Auth(t *testing.T) {
	cred := &socks5proto.Credential{Username: "user", Password: "pass"}
	proxyAddr, targets := fakeSocks5Proxy(t, cred, nil)

	conn, err := DialThroughChain([]config.Url{
		{
			Scheme:   constant.Socks5,
			BindAddr: proxyAddr,
			Auth:     &config.Auth{Username: cred.Username, Password: cred.Password},
		},
	}, "target.example:443")
	if err != nil {
		t.Fatalf("DialThroughChain: %v", err)
	}
	defer conn.Close()

	if got := <-targets; got != "target.example:443" {
		t.Errorf("request target = %q, want %q", got, "target.example:443")
	}
}

func TestDialThroughChainEmpty(t *testing.T) {
	if _, err := DialThroughChain(nil, "target.example:443"); err == nil {
		t.Fatal("DialThroughChain(nil) = nil error, want error")
	}
}

func TestDialThroughChainUnsupportedScheme(t *testing.T) {
	addr := acceptOnce(t)
	_, err := DialThroughChain([]config.Url{{Scheme: "ftp", BindAddr: addr}}, "target.example:443")
	if err == nil || !strings.Contains(err.Error(), "unsupported scheme") {
		t.Fatalf("error = %v, want unsupported scheme", err)
	}
}

func TestDialUdpAssociationNoChain(t *testing.T) {
	withForwardChain(t, nil)

	control, relay, err := DialUdpAssociation()
	if err != nil {
		t.Fatalf("DialUdpAssociation: %v", err)
	}
	if control != nil || relay != nil {
		t.Fatalf("control = %v, relay = %v, want nil", control, relay)
	}
}

func TestDialUdpAssociationSingleSocks5(t *testing.T) {
	relay := &socks5proto.Addr{Type: socks5proto.AddrIPv4, Host: "127.0.0.1", Port: 1080}
	proxyAddr, targets := fakeSocks5Proxy(t, nil, relay)
	withForwardChain(t, []config.Url{{Scheme: constant.Socks5, BindAddr: proxyAddr}})

	control, got, err := DialUdpAssociation()
	if err != nil {
		t.Fatalf("DialUdpAssociation: %v", err)
	}
	defer control.Close()

	if got.String() != relay.String() {
		t.Errorf("relay = %s, want %s", got, relay)
	}
	if target := <-targets; target != "0.0.0.0:0" {
		t.Errorf("request target = %q, want %q", target, "0.0.0.0:0")
	}
}

func TestDialUdpAssociationRejectsHTTP(t *testing.T) {
	withForwardChain(t, []config.Url{{Scheme: constant.HTTP, BindAddr: "127.0.0.1:1"}})

	_, _, err := DialUdpAssociation()
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("error = %v, want unsupported", err)
	}
}

func TestDialUdpAssociationRejectsMultiHop(t *testing.T) {
	withForwardChain(t, []config.Url{
		{Scheme: constant.Socks5, BindAddr: "127.0.0.1:1"},
		{Scheme: constant.Socks5, BindAddr: "127.0.0.1:2"},
	})

	_, _, err := DialUdpAssociation()
	if err == nil || !strings.Contains(err.Error(), "more than one hop") {
		t.Fatalf("error = %v, want multi-hop rejection", err)
	}
}
