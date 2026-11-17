package runner

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"gocks/internal/config"
	"gocks/internal/constant"
)

func makeTCPRule(addr string) config.Rule {
	return config.Rule{Listen: config.Endpoint{Scheme: constant.TCP, Addr: addr, Target: "127.0.0.1:1"}}
}

func makeUDPRule(addr string) config.Rule {
	return config.Rule{Listen: config.Endpoint{Scheme: constant.UDP, Addr: addr, Target: "127.0.0.1:1"}}
}

// reserveTCP reserves a loopback port and releases it immediately, so the
// returned address is usable by the runner.
func reserveTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func reserveUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

// requireFree retries until the address can be bound again, proving the runner
// released it.
func requireFree(t *testing.T, network, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var (
			closer interface{ Close() error }
			err    error
		)
		if network == "udp" {
			closer, err = net.ListenPacket(network, addr)
		} else {
			closer, err = net.Listen(network, addr)
		}
		if err == nil {
			closer.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s %s still in use: %v", network, addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRunWithoutRules verifies the empty configuration guard.
func TestRunWithoutRules(t *testing.T) {
	if err := Run(context.Background(), config.Config{}); err == nil {
		t.Fatal("Run err = nil, want error")
	}
}

// TestRunRejectsDuplicateListen verifies the exact-address conflict check.
func TestRunRejectsDuplicateListen(t *testing.T) {
	addr := reserveTCP(t)
	cfg := config.Config{Rules: []config.Rule{makeTCPRule(addr), makeTCPRule(addr)}}
	err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "both listen") {
		t.Fatalf("Run err = %v, want containing %q", err, "both listen")
	}
}

// TestRunBindsAllBeforeServing verifies that one unavailable port aborts the
// whole start and releases the listeners already bound.
func TestRunBindsAllBeforeServing(t *testing.T) {
	first := reserveTCP(t)

	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer blocked.Close()

	cfg := config.Config{Rules: []config.Rule{
		makeTCPRule(first),
		makeTCPRule(blocked.Addr().String()),
	}}
	err = Run(context.Background(), cfg)
	if err == nil {
		t.Fatal("Run err = nil, want bind error")
	}
	if !strings.Contains(err.Error(), "rule 2/2") {
		t.Errorf("err = %v, want containing %q", err, "rule 2/2")
	}

	// The first listener must have been closed during rollback.
	requireFree(t, "tcp", first)
}

// TestRunUnsupportedScheme verifies the bind guard.
func TestRunUnsupportedScheme(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{{
		Listen: config.Endpoint{Scheme: "foo", Addr: "127.0.0.1:1"},
	}}}
	err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "unsupported listen scheme") {
		t.Fatalf("Run err = %v, want containing %q", err, "unsupported listen scheme")
	}
}

// TestRunStopsOnCancel verifies that cancellation releases every listener,
// including the UDP one whose read blocks until the socket is closed.
func TestRunStopsOnCancel(t *testing.T) {
	tcpAddr := reserveTCP(t)
	udpAddr := reserveUDP(t)

	cfg := config.Config{Rules: []config.Rule{makeTCPRule(tcpAddr), makeUDPRule(udpAddr)}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()

	// Let the goroutines reach their serving loops before cancelling.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run err = %v, want nil after cancel", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	requireFree(t, "tcp", tcpAddr)
	requireFree(t, "udp", udpAddr)
}
