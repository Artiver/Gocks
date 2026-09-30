package tunnel

import (
	"bytes"
	"io"
	"net"
	"time"
)

// ReaderConn is a net.Conn whose reads come from reader while writes, closes
// and deadlines go to conn. It lets a proxy hand a buffered or pre-read stream
// to the transport without losing the bytes that follow.
type ReaderConn struct {
	reader io.Reader
	conn   net.Conn
}

// NewReaderConn wraps conn so that reads are served from reader.
func NewReaderConn(reader io.Reader, conn net.Conn) *ReaderConn {
	return &ReaderConn{reader: reader, conn: conn}
}

// NewPrefixConn wraps conn so that prefix, already consumed from the socket by
// protocol detection, is replayed before conn's own bytes.
func NewPrefixConn(prefix []byte, conn net.Conn) *ReaderConn {
	return NewReaderConn(io.MultiReader(bytes.NewReader(prefix), conn), conn)
}

func (c *ReaderConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *ReaderConn) Write(p []byte) (int, error) { return c.conn.Write(p) }
func (c *ReaderConn) Close() error                { return c.conn.Close() }
func (c *ReaderConn) LocalAddr() net.Addr         { return c.conn.LocalAddr() }
func (c *ReaderConn) RemoteAddr() net.Addr        { return c.conn.RemoteAddr() }

func (c *ReaderConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *ReaderConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *ReaderConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *ReaderConn) CloseWrite() error {
	if cw, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return ErrNotSupported
}

func (c *ReaderConn) CloseRead() error {
	if cr, ok := c.conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return ErrNotSupported
}
