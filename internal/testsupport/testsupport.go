// Package testsupport provides the network test doubles shared by the proxy,
// forward and dialer tests: echo servers, a silent listener, and a configurable
// SOCKS5 upstream.
package testsupport

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	socks5proto "gocks/internal/protocol/socks5"
)

// TCPServer runs serve for every accepted connection on loopback and returns
// the address it listens on. The listener is closed when the test ends.
func TCPServer(t *testing.T, serve func(net.Conn)) string {
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
			go serve(c)
		}
	}()

	return ln.Addr().String()
}

// TCPEcho starts a TCP server that echoes every byte back.
func TCPEcho(t *testing.T) string {
	t.Helper()
	return TCPServer(t, func(c net.Conn) {
		defer c.Close()
		io.Copy(c, c)
	})
}

// SilentListener starts a TCP server that accepts a connection, reads a couple
// of bytes and closes it, so a protocol handshake against it fails even though
// the TCP connect itself succeeds.
func SilentListener(t *testing.T) string {
	t.Helper()
	return TCPServer(t, func(c net.Conn) {
		defer c.Close()
		c.Read(make([]byte, 2))
	})
}

// ClosedAddr returns a loopback address that nothing is listening on.
func ClosedAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TargetLog records, in order, the targets a relay double was asked to reach,
// so a test can prove which hops were traversed.
type TargetLog struct {
	mu      sync.Mutex
	targets []string
}

// Add records one target.
func (l *TargetLog) Add(target string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.targets = append(l.targets, target)
}

// snapshot returns the targets recorded so far.
func (l *TargetLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.targets...)
}

// Assert fails the test unless the recorded targets are exactly want.
func (l *TargetLog) Assert(t *testing.T, want ...string) {
	t.Helper()

	got := l.snapshot()
	if len(got) != len(want) {
		t.Fatalf("relay targets=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("relay target[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

// defaultUDPRelay is the relay address Socks5Upstream advertises for a UDP
// ASSOCIATE when Socks5Options.RelayAddr is nil.
var defaultUDPRelay = &socks5proto.Addr{Type: socks5proto.AddrIPv4, Host: "127.0.0.1", Port: 12345}

// Socks5Options configures the SOCKS5 upstream returned by Socks5Upstream.
type Socks5Options struct {
	// Cred requires username/password authentication when set.
	Cred *socks5proto.Credential

	// ReplyRep answers the request with this code instead of connecting. The
	// zero value is RepSucceeded, which means "handle the request normally".
	ReplyRep byte

	// ReplyAddr is the bound address reported for a successful CONNECT. When
	// nil, the address the upstream really used is reported, so a test can
	// make the reply longer than the classic 10 bytes.
	ReplyAddr *socks5proto.Addr

	// RelayAddr is reported for a UDP ASSOCIATE; nil means 127.0.0.1:12345.
	RelayAddr *socks5proto.Addr

	// Log records the targets a CONNECT was asked to reach.
	Log *TargetLog
}

// Socks5Upstream starts a SOCKS5 proxy that performs the handshake, answers one
// request and then relays the connection to the requested target. A refusal
// (ReplyRep) or a failed dial is reported with the matching reply code, and a
// UDP ASSOCIATE is answered with the relay address and kept alive.
func Socks5Upstream(t *testing.T, opts Socks5Options) string {
	t.Helper()
	return TCPServer(t, func(c net.Conn) { serveSocks5(c, opts) })
}

func serveSocks5(c net.Conn, opts Socks5Options) {
	defer c.Close()

	selector := socks5proto.NewServerSelector()
	if opts.Cred != nil {
		selector = socks5proto.NewServerSelector(*opts.Cred)
	}
	if _, err := socks5proto.ServerHandshake(c, selector); err != nil {
		return
	}

	req, err := socks5proto.ReadRequest(c)
	if err != nil {
		return
	}

	if opts.ReplyRep != socks5proto.RepSucceeded {
		socks5proto.NewReply(opts.ReplyRep, nil).Write(c)
		return
	}

	switch req.Cmd {
	case socks5proto.CmdUDP:
		relay := opts.RelayAddr
		if relay == nil {
			relay = defaultUDPRelay
		}
		if err := socks5proto.NewReply(socks5proto.RepSucceeded, relay).Write(c); err != nil {
			return
		}
		// Keep the association alive until the client closes the control conn.
		io.Copy(io.Discard, c)
		return

	case socks5proto.CmdConnect:
		if req.Addr == nil {
			socks5proto.NewReply(socks5proto.RepCmdUnsupported, nil).Write(c)
			return
		}

	default:
		socks5proto.NewReply(socks5proto.RepCmdUnsupported, nil).Write(c)
		return
	}

	target := req.Addr.String()
	if opts.Log != nil {
		opts.Log.Add(target)
	}

	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		socks5proto.NewReply(socks5proto.RepHostUnreachable, nil).Write(c)
		return
	}
	defer upstream.Close()

	reply := socks5proto.NewReply(socks5proto.RepSucceeded, opts.ReplyAddr)
	if reply.Addr == nil {
		if bound, err := socks5proto.NewAddr(upstream.LocalAddr().String()); err == nil {
			reply.Addr = bound
		}
	}
	if err := reply.Write(c); err != nil {
		return
	}

	relay(c, upstream)
}

// relay copies bytes in both directions and returns once either side is done.
func relay(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, client)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
}

// AssertEcho writes msg through conn and fails the test unless it comes back.
func AssertEcho(t *testing.T, conn net.Conn, msg string) {
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
