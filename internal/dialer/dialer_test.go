package dialer

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"gocks/internal/config"
	"gocks/internal/constant"
	socks5proto "gocks/internal/protocol/socks5"
)

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

// startRelay runs a SOCKS5 server that connects to the requested target, so it
// can stand in for any hop of a chain. It records the targets it was asked for.
func startRelay(t *testing.T) (string, *targetLog) {
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
			go serveRelay(c, log)
		}
	}()

	return ln.Addr().String(), log
}

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

func serveRelay(c net.Conn, log *targetLog) {
	defer c.Close()

	if _, err := socks5proto.ServerHandshake(c, socks5proto.NewServerSelector()); err != nil {
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

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, c); done <- struct{}{} }()
	go func() { io.Copy(c, upstream); done <- struct{}{} }()
	<-done
}

// startUDPAssociateStub answers a SOCKS5 UDP ASSOCIATE with a fixed relay
// address and keeps the control connection open.
func startUDPAssociateStub(t *testing.T) string {
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
				if _, err := socks5proto.ServerHandshake(c, socks5proto.NewServerSelector()); err != nil {
					return
				}
				if _, err := socks5proto.ReadRequest(c); err != nil {
					return
				}
				socks5proto.NewReply(socks5proto.RepSucceeded, &socks5proto.Addr{
					Type: socks5proto.AddrIPv4, Host: "127.0.0.1", Port: 12345,
				}).Write(c)
				io.Copy(io.Discard, c)
			}(c)
		}
	}()

	return ln.Addr().String()
}

func setChain(t *testing.T, hops ...config.Url) {
	t.Helper()

	previous := config.ForwardChain
	config.ForwardChain = hops
	t.Cleanup(func() { config.ForwardChain = previous })
}

func socks5Hop(bindAddr string) config.Url {
	return config.Url{Scheme: constant.Socks5, BindAddr: bindAddr}
}

func TestDialTcpConnectionDirect(t *testing.T) {
	setChain(t)

	target := startEcho(t)
	conn, err := DialTcpConnection(target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, "direct")
}

func TestDialTcpConnectionSingleHop(t *testing.T) {
	relay, log := startRelay(t)
	setChain(t, socks5Hop(relay))

	target := startEcho(t)
	conn, err := DialTcpConnection(target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, "single-hop")
	assertTargets(t, log, target)
}

func TestDialTcpConnectionTwoHops(t *testing.T) {
	far, farLog := startRelay(t)
	near, nearLog := startRelay(t)
	setChain(t, socks5Hop(near), socks5Hop(far))

	target := startEcho(t)
	conn, err := DialTcpConnection(target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, "two-hops-through-dialer")

	// The near hop forwards to the far hop; only the far hop sees the target.
	assertTargets(t, nearLog, far)
	assertTargets(t, farLog, target)
}

func TestDialUdpAssociationDirect(t *testing.T) {
	setChain(t)

	control, relay, err := DialUdpAssociation()
	if err != nil {
		t.Fatalf("udp association: %v", err)
	}
	if control != nil || relay != nil {
		t.Fatalf("expected a direct association, got control=%v relay=%v", control, relay)
	}
}

func TestDialUdpAssociationSingleSocks5Hop(t *testing.T) {
	hop := startUDPAssociateStub(t)
	setChain(t, socks5Hop(hop))

	control, relay, err := DialUdpAssociation()
	if err != nil {
		t.Fatalf("udp association: %v", err)
	}
	defer control.Close()

	if relay == nil {
		t.Fatal("missing relay address")
	}
	if relay.String() != "127.0.0.1:12345" {
		t.Fatalf("relay=%s want 127.0.0.1:12345", relay)
	}
}

func TestDialUdpAssociationRejectsHTTPHop(t *testing.T) {
	setChain(t, config.Url{Scheme: constant.HTTP, BindAddr: "127.0.0.1:1"})

	if _, _, err := DialUdpAssociation(); err == nil {
		t.Fatal("expected UDP over an HTTP hop to be refused")
	}
}

func TestDialUdpAssociationRejectsMultiHopChain(t *testing.T) {
	setChain(t, socks5Hop("127.0.0.1:1"), socks5Hop("127.0.0.1:2"))

	control, relay, err := DialUdpAssociation()
	if err == nil {
		t.Fatal("expected a multi-hop UDP association to be refused")
	}
	if control != nil || relay != nil {
		t.Fatalf("expected no association, got control=%v relay=%v", control, relay)
	}
	if !strings.Contains(err.Error(), "more than one hop") {
		t.Fatalf("error=%q should explain the chain limit", err)
	}
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
