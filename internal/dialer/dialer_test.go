package dialer

import (
	"strings"
	"testing"

	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/testsupport"
)

// startRelay runs a SOCKS5 upstream that connects to the requested target, so
// it can stand in for any hop of a chain. It records the targets it was asked
// for.
func startRelay(t *testing.T) (string, *testsupport.TargetLog) {
	t.Helper()

	log := &testsupport.TargetLog{}
	addr := testsupport.Socks5Upstream(t, testsupport.Socks5Options{Log: log})
	return addr, log
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

	target := testsupport.TCPEcho(t)
	conn, err := DialTcpConnection(target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	testsupport.AssertEcho(t, conn, "direct")
}

func TestDialTcpConnectionSingleHop(t *testing.T) {
	relay, log := startRelay(t)
	setChain(t, socks5Hop(relay))

	target := testsupport.TCPEcho(t)
	conn, err := DialTcpConnection(target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	testsupport.AssertEcho(t, conn, "single-hop")
	log.Assert(t, target)
}

func TestDialTcpConnectionTwoHops(t *testing.T) {
	far, farLog := startRelay(t)
	near, nearLog := startRelay(t)
	setChain(t, socks5Hop(near), socks5Hop(far))

	target := testsupport.TCPEcho(t)
	conn, err := DialTcpConnection(target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	testsupport.AssertEcho(t, conn, "two-hops-through-dialer")

	// The near hop forwards to the far hop; only the far hop sees the target.
	nearLog.Assert(t, far)
	farLog.Assert(t, target)
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
	hop := testsupport.Socks5Upstream(t, testsupport.Socks5Options{})
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
