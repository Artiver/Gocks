package tcp

import (
	"net"
	"testing"
	"time"

	"gocks/internal/config"
	"gocks/internal/constant"
	socks5proto "gocks/internal/protocol/socks5"
	"gocks/internal/testsupport"
)

// TestHandleConnectionUsesForwardChain proves -F applies to TCP port
// forwarding: the upstream hop is asked to reach the target, so a hop that
// refuses fails the forward even though the target is directly reachable.
// Without the chain the relay would succeed and echo the byte back.
func TestHandleConnectionUsesForwardChain(t *testing.T) {
	previousConfig := config.ProxyConfig
	previousChain := config.ForwardChain
	t.Cleanup(func() {
		config.ProxyConfig = previousConfig
		config.ForwardChain = previousChain
	})

	target := testsupport.TCPEcho(t)
	upstream := testsupport.Socks5Upstream(t, testsupport.Socks5Options{
		ReplyRep: socks5proto.RepHostUnreachable,
	})

	config.ProxyConfig.TranAddr = target
	config.ForwardChain = []config.Url{{Scheme: constant.Socks5, BindAddr: upstream}}

	proxySide, clientSide := net.Pipe()
	defer clientSide.Close()

	done := make(chan struct{})
	go func() {
		handleConnection(proxySide)
		close(done)
	}()

	// The refusing hop must stop the relay before any byte is echoed. A pipe
	// write only succeeds once the other side reads it.
	if err := clientSide.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := clientSide.Write([]byte("x")); err == nil {
		buf := make([]byte, 1)
		if _, err := clientSide.Read(buf); err == nil {
			t.Fatal("expected the refusing upstream hop to fail the forward")
		}
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConnection did not return")
	}
}
