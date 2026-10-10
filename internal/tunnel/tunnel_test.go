package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fakes & helpers
// ---------------------------------------------------------------------------

// tcpPair returns two ends of a real loopback TCP connection. Unlike net.Pipe
// (Go 1.26), TCP connections implement CloseWrite/CloseRead, which is required
// to test bidirectional transport with proper half-close semantics.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	type acceptRes struct {
		c   net.Conn
		err error
	}
	ch := make(chan acceptRes, 1)
	go func() {
		c, err := ln.Accept()
		ch <- acceptRes{c, err}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("Dial: %v", err)
	}
	res := <-ch
	ln.Close()
	if res.err != nil {
		client.Close()
		t.Fatalf("Accept: %v", res.err)
	}
	return client, res.c
}

// readErrConn is a net.Conn whose Read always returns a configured non-EOF
// error, used to exercise copyHalf's non-EOF read-error branch.
type readErrConn struct {
	readErr error
}

func (c *readErrConn) Read(p []byte) (int, error)         { return 0, c.readErr }
func (c *readErrConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *readErrConn) Close() error                       { return nil }
func (c *readErrConn) LocalAddr() net.Addr                { return &net.IPAddr{} }
func (c *readErrConn) RemoteAddr() net.Addr               { return &net.IPAddr{} }
func (c *readErrConn) SetDeadline(t time.Time) error      { return nil }
func (c *readErrConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *readErrConn) SetWriteDeadline(t time.Time) error { return nil }

// shortWriteConn wraps a net.Conn and reports a short write (1 byte written,
// nil error) for any buffer larger than 1 byte, to exercise copyHalf's
// io.ErrShortWrite branch.
type shortWriteConn struct {
	net.Conn
}

func (c *shortWriteConn) Write(p []byte) (int, error) {
	if len(p) > 1 {
		return 1, nil
	}
	return c.Conn.Write(p)
}

// closeWriteErrConn wraps a net.Conn and makes CloseWrite return a configured
// error, to exercise closeWrite's fallback-to-Close branch.
type closeWriteErrConn struct {
	net.Conn
	closeWriteErr error
}

func (c *closeWriteErrConn) CloseWrite() error { return c.closeWriteErr }

// ---------------------------------------------------------------------------
// ErrNotSupported
// ---------------------------------------------------------------------------

func TestErrNotSupported(t *testing.T) {
	if ErrNotSupported == nil {
		t.Fatal("ErrNotSupported is nil")
	}
	if ErrNotSupported.Error() == "" {
		t.Fatal("ErrNotSupported has empty message")
	}
}

// ---------------------------------------------------------------------------
// isBenign
// ---------------------------------------------------------------------------

func TestIsBenign(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, true},
		{"io.EOF", io.EOF, true},
		{"io.ErrClosedPipe", io.ErrClosedPipe, true},
		{"net.ErrClosed", net.ErrClosed, true},
		{"context.Canceled", context.Canceled, true},
		{"wrapped EOF", fmt.Errorf("wrapped: %w", io.EOF), true},
		{"wrapped Canceled", fmt.Errorf("wrapped: %w", context.Canceled), true},
		{"wrapped ErrClosedPipe", fmt.Errorf("wrapped: %w", io.ErrClosedPipe), true},
		{"wrapped net.ErrClosed", fmt.Errorf("wrapped: %w", net.ErrClosed), true},
		{"random error", errors.New("something broke"), false},
		{"plain text not sentinel", errors.New("use of closed network connection"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBenign(tt.err); got != tt.want {
				t.Errorf("isBenign(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestIsBenign_RealClosedListener verifies that the error returned by Accept
// on a closed listener is recognized as benign (it wraps net.ErrClosed).
func TestIsBenign_RealClosedListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ln.Close()
	_, err = ln.Accept()
	if err == nil {
		t.Fatal("expected error from Accept on closed listener")
	}
	if !isBenign(err) {
		t.Errorf("isBenign(closed-listener Accept) = false, want true; err=%v", err)
	}
}

// ---------------------------------------------------------------------------
// TransportData / TransportDataStats / TransportDataContextStats
// ---------------------------------------------------------------------------

// runBidirectional wires two TCP pairs into a source<->target transport, sends
// clientPayload from the client side and serverPayload from the server side,
// then asserts the returned byte counts and delivered payloads match exactly.
// TCP is used so CloseWrite properly half-closes each direction.
func runBidirectional(t *testing.T, clientPayload, serverPayload []byte) TransportStats {
	t.Helper()
	clientSide, source := tcpPair(t)
	target, serverSide := tcpPair(t)
	defer clientSide.Close()
	defer serverSide.Close()

	var serverReceived, clientReceived []byte
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		serverReceived, _ = io.ReadAll(serverSide)
	}()
	go func() {
		defer wg.Done()
		clientReceived, _ = io.ReadAll(clientSide)
	}()

	go func() {
		clientSide.Write(clientPayload)
		pipeCloseWrite(clientSide)
	}()
	go func() {
		serverSide.Write(serverPayload)
		pipeCloseWrite(serverSide)
	}()

	stats, err := TransportDataStats(source, target)
	if err != nil {
		t.Fatalf("TransportDataStats: %v", err)
	}
	wg.Wait()

	if stats.SourceToTarget != int64(len(clientPayload)) {
		t.Errorf("SourceToTarget = %d, want %d", stats.SourceToTarget, len(clientPayload))
	}
	if stats.TargetToSource != int64(len(serverPayload)) {
		t.Errorf("TargetToSource = %d, want %d", stats.TargetToSource, len(serverPayload))
	}
	if !bytes.Equal(serverReceived, clientPayload) {
		t.Errorf("server received %d bytes, want %d", len(serverReceived), len(clientPayload))
	}
	if !bytes.Equal(clientReceived, serverPayload) {
		t.Errorf("client received %d bytes, want %d", len(clientReceived), len(serverPayload))
	}
	return stats
}

func TestTransportDataStats_SmallPayload(t *testing.T) {
	runBidirectional(t, []byte("hello from client"), []byte("hi from server"))
}

func TestTransportDataStats_LargePayload(t *testing.T) {
	// Larger than copyHalf's 32 KiB internal buffer.
	runBidirectional(t, bytes.Repeat([]byte("C"), 100*1024), bytes.Repeat([]byte("S"), 100*1024))
}

func TestTransportDataStats_Empty(t *testing.T) {
	stats := runBidirectional(t, nil, nil)
	if stats.SourceToTarget != 0 || stats.TargetToSource != 0 {
		t.Errorf("expected zero stats, got %+v", stats)
	}
}

func TestTransportData(t *testing.T) {
	clientSide, source := tcpPair(t)
	target, serverSide := tcpPair(t)
	defer clientSide.Close()
	defer serverSide.Close()

	payload := []byte("test payload")

	var received []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		received, _ = io.ReadAll(serverSide)
	}()

	go func() {
		clientSide.Write(payload)
		pipeCloseWrite(clientSide)
	}()
	go func() {
		pipeCloseWrite(serverSide)
	}()

	if err := TransportData(source, target); err != nil {
		t.Fatalf("TransportData: %v", err)
	}
	wg.Wait()

	if !bytes.Equal(received, payload) {
		t.Errorf("received %q, want %q", received, payload)
	}
}

// TestTransportDataContextStats_Cancel verifies that cancelling the context
// mid-transfer makes the function return promptly instead of hanging. Uses
// net.Pipe since cancel triggers forceClose regardless of half-close support.
func TestTransportDataContextStats_Cancel(t *testing.T) {
	clientSide, source := net.Pipe()
	target, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		TransportDataContextStats(ctx, source, target)
		close(done)
	}()

	// Give the goroutines time to start and block on Read.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// returned promptly
	case <-time.After(3 * time.Second):
		t.Fatal("TransportDataContextStats hung after cancel")
	}
}

// ---------------------------------------------------------------------------
// copyHalf (white-box)
// ---------------------------------------------------------------------------

func TestCopyHalf_ReadError(t *testing.T) {
	dst, dstOther := net.Pipe()
	defer dst.Close()
	defer dstOther.Close()
	go io.Copy(io.Discard, dstOther)

	src := &readErrConn{readErr: errors.New("read failure")}
	n, err := copyHalf(context.Background(), dst, src)
	if err == nil || err.Error() != "read failure" {
		t.Errorf("err = %v, want 'read failure'", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
}

func TestCopyHalf_ContextCanceled(t *testing.T) {
	src, srcOther := net.Pipe()
	dst, dstOther := net.Pipe()
	defer srcOther.Close()
	defer dstOther.Close()
	defer src.Close()
	defer dst.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	go io.Copy(io.Discard, dstOther)

	n, err := copyHalf(ctx, dst, src)
	if err != context.Canceled {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
}

func TestCopyHalf_WriteError(t *testing.T) {
	src, srcOther := net.Pipe()
	dst, dstOther := net.Pipe()
	defer srcOther.Close()
	defer src.Close()
	defer dst.Close()

	// Close the peer so dst.Write fails.
	dstOther.Close()

	go func() {
		srcOther.Write([]byte("data"))
		srcOther.Close() // net.Pipe lacks CloseWrite; Close to unblock src.Read
	}()

	_, err := copyHalf(context.Background(), dst, src)
	if err == nil {
		t.Fatal("expected write error, got nil")
	}
}

func TestCopyHalf_ShortWrite(t *testing.T) {
	src, srcOther := net.Pipe()
	dst, dstOther := net.Pipe()
	defer srcOther.Close()
	defer dstOther.Close()
	defer src.Close()
	defer dst.Close()

	sw := &shortWriteConn{Conn: dst}

	go func() {
		srcOther.Write([]byte("hello"))
		srcOther.Close()
	}()
	go io.Copy(io.Discard, dstOther)

	_, err := copyHalf(context.Background(), sw, src)
	if err != io.ErrShortWrite {
		t.Errorf("err = %v, want io.ErrShortWrite", err)
	}
}

// ---------------------------------------------------------------------------
// closeWrite / closeRead / forceClose (white-box)
// ---------------------------------------------------------------------------

func TestCloseWrite_Supported(t *testing.T) {
	a, b := tcpPair(t)
	defer a.Close()
	defer b.Close()
	closeWrite(a) // a.CloseWrite()
	buf := make([]byte, 1)
	if _, err := b.Read(buf); err != io.EOF {
		t.Errorf("expected EOF after CloseWrite, got %v", err)
	}
}

func TestCloseWrite_NotSupported(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	pc := &plainConn{c: a}
	closeWrite(pc) // falls back to Close
	buf := make([]byte, 1)
	if _, err := b.Read(buf); err != io.EOF {
		t.Errorf("expected EOF after fallback Close, got %v", err)
	}
}

func TestCloseWrite_ErrorFallback(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	cw := &closeWriteErrConn{Conn: a, closeWriteErr: errors.New("closewrite failed")}
	closeWrite(cw) // CloseWrite fails -> Close()
	buf := make([]byte, 1)
	if _, err := b.Read(buf); err != io.EOF {
		t.Errorf("expected EOF after fallback Close, got %v", err)
	}
}

func TestCloseRead_Supported(t *testing.T) {
	a, b := tcpPair(t)
	defer a.Close()
	defer b.Close()
	closeRead(a) // a.CloseRead(), should not panic
}

func TestCloseRead_NotSupported(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	closeRead(&plainConn{c: a}) // no-op, should not panic
}

func TestForceClose(t *testing.T) {
	a, b := net.Pipe()
	forceClose(a, b, nil)
	if _, err := a.Write([]byte("x")); err == nil {
		t.Error("expected a.Write to fail after forceClose")
	}
	if _, err := b.Write([]byte("x")); err == nil {
		t.Error("expected b.Write to fail after forceClose")
	}
}

// ---------------------------------------------------------------------------
// Half-close behavior: CloseWrite on one end yields io.EOF on the peer while
// the opposite direction remains drainable. Uses TCP since net.Pipe lacks
// CloseWrite.
// ---------------------------------------------------------------------------

func TestHalfClose_PeerSeesEOF(t *testing.T) {
	a, b := tcpPair(t)
	defer a.Close()
	defer b.Close()

	go func() {
		a.Write([]byte("data"))
		pipeCloseWrite(a)
	}()

	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "data" {
		t.Errorf("got %q, want %q", got, "data")
	}
}

func TestHalfClose_OppositeDirectionDrainable(t *testing.T) {
	a, b := tcpPair(t)
	defer a.Close()
	defer b.Close()

	// a half-closes its write side; b should still be able to write to a
	// (i.e. the read side of a is still open) and a should receive it.
	if err := pipeCloseWrite(a); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// b reads EOF from a's closed write side.
	buf := make([]byte, 1)
	if _, err := b.Read(buf); err != io.EOF {
		t.Errorf("expected EOF on b.Read, got %v", err)
	}

	// b writes the other direction; a should still receive it.
	go func() {
		b.Write([]byte("reverse"))
		pipeCloseWrite(b)
	}()

	got, err := io.ReadAll(a)
	if err != nil {
		t.Fatalf("ReadAll a: %v", err)
	}
	if string(got) != "reverse" {
		t.Errorf("got %q, want %q", got, "reverse")
	}
}
