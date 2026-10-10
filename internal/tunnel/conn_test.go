package tunnel

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// plainConn wraps a net.Conn but deliberately does NOT implement CloseWrite
// or CloseRead, so the ErrNotSupported fallback paths in ReaderConn are
// exercised. It still delegates every net.Conn method to the underlying conn.
type plainConn struct {
	c net.Conn
}

func (p *plainConn) Read(b []byte) (int, error)         { return p.c.Read(b) }
func (p *plainConn) Write(b []byte) (int, error)        { return p.c.Write(b) }
func (p *plainConn) Close() error                       { return p.c.Close() }
func (p *plainConn) LocalAddr() net.Addr                { return p.c.LocalAddr() }
func (p *plainConn) RemoteAddr() net.Addr               { return p.c.RemoteAddr() }
func (p *plainConn) SetDeadline(t time.Time) error      { return p.c.SetDeadline(t) }
func (p *plainConn) SetReadDeadline(t time.Time) error  { return p.c.SetReadDeadline(t) }
func (p *plainConn) SetWriteDeadline(t time.Time) error { return p.c.SetWriteDeadline(t) }

// pipeCloseWrite half-closes the write side of c when supported (real TCP
// connections support it). It returns ErrNotSupported otherwise. Go 1.26's
// net.Pipe endpoints do NOT implement CloseWrite, so callers that only use
// net.Pipe should use Close() instead to signal EOF to the peer.
func pipeCloseWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return ErrNotSupported
}

// TestNewReaderConn_ReadFromReader verifies that reads are served from the
// custom reader rather than the underlying conn.
func TestNewReaderConn_ReadFromReader(t *testing.T) {
	data := []byte("custom reader data")
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	rc := NewReaderConn(bytes.NewReader(data), a)
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

// TestNewPrefixConn_ReplaysPrefixThenContinues verifies that NewPrefixConn
// replays prefix bytes from memory before continuing to read from the
// underlying conn. Uses net.Pipe (Close to signal EOF since Pipe lacks
// CloseWrite).
func TestNewPrefixConn_ReplaysPrefixThenContinues(t *testing.T) {
	prefix := []byte("PREFIX")
	rest := []byte("-REST")
	want := append(append([]byte{}, prefix...), rest...)

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// Peer writes rest then closes (net.Pipe lacks CloseWrite).
	go func() {
		b.Write(rest)
		b.Close()
	}()

	// Wrap: reads replay prefix (from memory) then continue with rest (from a).
	rc := NewPrefixConn(prefix, a)
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestNewPrefixConn_AfterPreRead verifies the full protocol-detection scenario:
// a prefix is consumed directly from the conn, then NewPrefixConn replays it so
// the transport still sees the complete stream. Uses a real TCP connection so
// CloseWrite properly half-closes without affecting the read direction.
func TestNewPrefixConn_AfterPreRead(t *testing.T) {
	prefix := []byte("PREFIX")
	rest := []byte("-REST")
	want := append(append([]byte{}, prefix...), rest...)

	client, server := tcpPair(t)
	defer client.Close()
	defer server.Close()

	// Server sends prefix+rest then half-closes.
	go func() {
		server.Write(prefix)
		server.Write(rest)
		pipeCloseWrite(server)
	}()

	// Pre-read prefix directly from client (protocol detection).
	pre := make([]byte, len(prefix))
	if _, err := io.ReadFull(client, pre); err != nil {
		t.Fatalf("prefetch: %v", err)
	}

	// Wrap: replay prefix then continue from client.
	rc := NewPrefixConn(prefix, client)
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestReaderConn_WriteDelegates verifies writes go to the underlying conn.
func TestReaderConn_WriteDelegates(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	rc := NewReaderConn(bytes.NewReader(nil), a)
	payload := []byte("write test")

	go func() {
		if _, err := rc.Write(payload); err != nil {
			t.Errorf("Write: %v", err)
		}
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("got %q, want %q", got, payload)
	}
}

// TestReaderConn_Close verifies Close delegates to the underlying conn and the
// peer observes EOF.
func TestReaderConn_Close(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	rc := NewReaderConn(bytes.NewReader(nil), a)
	if err := rc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := b.Read(buf); err != io.EOF {
		t.Errorf("expected io.EOF after Close, got %v", err)
	}
}

// TestReaderConn_Addrs verifies LocalAddr/RemoteAddr delegate to the underlying conn.
func TestReaderConn_Addrs(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	rc := NewReaderConn(bytes.NewReader(nil), a)
	if rc.LocalAddr().String() != a.LocalAddr().String() {
		t.Error("LocalAddr mismatch")
	}
	if rc.RemoteAddr().String() != a.RemoteAddr().String() {
		t.Error("RemoteAddr mismatch")
	}
}

// TestReaderConn_SetDeadlines verifies all deadline setters delegate.
func TestReaderConn_SetDeadlines(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	rc := NewReaderConn(bytes.NewReader(nil), a)
	d := time.Now().Add(time.Second)
	if err := rc.SetDeadline(d); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}
	if err := rc.SetReadDeadline(d); err != nil {
		t.Errorf("SetReadDeadline: %v", err)
	}
	if err := rc.SetWriteDeadline(d); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}
}

// TestReaderConn_CloseWriteCloseRead_Supported verifies that when the underlying
// conn implements CloseWrite/CloseRead (real TCP connections do), ReaderConn
// delegates to them.
func TestReaderConn_CloseWriteCloseRead_Supported(t *testing.T) {
	a, b := tcpPair(t)
	defer a.Close()
	defer b.Close()
	rc := NewReaderConn(bytes.NewReader(nil), a)
	if err := rc.CloseWrite(); err != nil {
		t.Errorf("CloseWrite: %v", err)
	}
	if err := rc.CloseRead(); err != nil {
		t.Errorf("CloseRead: %v", err)
	}
}

// TestReaderConn_CloseWriteCloseRead_NotSupported verifies that when the
// underlying conn does NOT implement CloseWrite/CloseRead, ReaderConn returns
// ErrNotSupported.
func TestReaderConn_CloseWriteCloseRead_NotSupported(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	rc := NewReaderConn(bytes.NewReader(nil), &plainConn{c: a})
	if err := rc.CloseWrite(); err != ErrNotSupported {
		t.Errorf("CloseWrite = %v, want ErrNotSupported", err)
	}
	if err := rc.CloseRead(); err != ErrNotSupported {
		t.Errorf("CloseRead = %v, want ErrNotSupported", err)
	}
}
