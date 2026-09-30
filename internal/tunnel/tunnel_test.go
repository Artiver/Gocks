package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// tcpPair returns the two ends of a fresh loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	return c, r.c
}

func TestTransportDataHalfClose(t *testing.T) {
	a1, a2 := tcpPair(t)
	b1, b2 := tcpPair(t)
	defer a1.Close()
	defer a2.Close()
	defer b1.Close()
	defer b2.Close()

	done := make(chan error, 1)
	go func() { done <- TransportData(&a2, &b1) }()

	// a -> b
	if _, err := a1.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(b2, got); err != nil {
		t.Fatalf("a->b: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("a->b got %q", got)
	}

	// Half-closing a's write side must surface as EOF on b.
	if err := a1.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	b2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := b2.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF on b2, got %v", err)
	}

	// The other direction must still work after the half-close.
	if _, err := b2.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	got2 := make([]byte, 5)
	if _, err := io.ReadFull(a1, got2); err != nil {
		t.Fatalf("b->a: %v", err)
	}
	if string(got2) != "world" {
		t.Fatalf("b->a got %q", got2)
	}

	b2.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("TransportData did not return after both sides closed")
	}
}

// TestTransportDataFullCloseFallback verifies that when a connection cannot be
// half-closed (net.Pipe), the transport closes it outright so the other
// direction is unblocked instead of waiting for the idle timeout.
func TestTransportDataFullCloseFallback(t *testing.T) {
	a, b := net.Pipe()
	c, d := net.Pipe()

	done := make(chan error, 1)
	go func() { done <- TransportData(&a, &c) }()

	if _, err := b.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 1)
	if _, err := io.ReadFull(d, got); err != nil {
		t.Fatal(err)
	}
	if got[0] != 'x' {
		t.Fatalf("got %q", got)
	}

	b.Close()

	d.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := d.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF on d, got %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected transport error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TransportData did not return promptly")
	}
}

func TestTransportDataContextCancel(t *testing.T) {
	a, b := net.Pipe()
	c, d := net.Pipe()
	defer b.Close()
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- TransportDataContext(ctx, &a, &c) }()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TransportDataContext did not return after cancel")
	}
}
