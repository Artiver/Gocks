package server

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestServeListenerHandlesConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handled := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- ServeListener(ctx, "test", ln, func(c net.Conn) {
			defer c.Close()
			handled <- struct{}{}
		})
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	select {
	case <-handled:
	case <-time.After(5 * time.Second):
		t.Fatal("connection was not handed to the handler")
	}

	// Cancelling the context must stop the loop with a nil error.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeListener returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeListener did not return after cancel")
	}
}

func TestServeReportsListenError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Port 70000 is out of range, so the listener cannot be created.
	if err := Serve(ctx, "test", "127.0.0.1:70000", func(net.Conn) {}); err == nil {
		t.Fatal("expected a listen error")
	}
}
