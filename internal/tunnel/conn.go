package tunnel

import (
	"bytes"
	"io"
	"net"
	"time"
)

type ReaderConn struct {
	reader io.Reader
	conn   net.Conn
}

func NewReaderConn(reader io.Reader, conn net.Conn) *ReaderConn {
	return &ReaderConn{reader: reader, conn: conn}
}

func (c *ReaderConn) Read(p []byte) (int, error)         { return c.reader.Read(p) }
func (c *ReaderConn) Write(p []byte) (int, error)        { return c.conn.Write(p) }
func (c *ReaderConn) Close() error                       { return c.conn.Close() }
func (c *ReaderConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *ReaderConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *ReaderConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *ReaderConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *ReaderConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

type PrefixConn struct {
	prefix *bytes.Reader
	conn   net.Conn
}

func NewPrefixConn(prefix []byte, conn net.Conn) *PrefixConn {
	return &PrefixConn{prefix: bytes.NewReader(prefix), conn: conn}
}

func (c *PrefixConn) Read(p []byte) (int, error) {
	if c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	return c.conn.Read(p)
}
func (c *PrefixConn) Write(p []byte) (int, error)        { return c.conn.Write(p) }
func (c *PrefixConn) Close() error                       { return c.conn.Close() }
func (c *PrefixConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *PrefixConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *PrefixConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *PrefixConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *PrefixConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
