package utils

import (
	"Gocks/forward"
	"Gocks/global"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func FormatAddress(ip string, port uint16) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	} else {
		return fmt.Sprintf("%s:%d", ip, port)
	}
}

// ReaderConn 用指定的 reader 作为 Read 源，其余操作委托给底层 conn。
// 用于将 bufio.Reader 的缓冲数据连同后续连接数据一起透传。
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

// PrefixConn 先读取前缀字节，再委托给底层连接的 Read。
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

// TransportData 在两个连接之间双向转发数据，直到双方都完成。
// 修复了原实现的 goroutine 泄漏问题：通过 CloseWrite 半关闭通知对端，
// 并等待两个方向都结束。支持 idle timeout 防止空闲连接永久挂起。
func TransportData(source, target *net.Conn) error {
	errCh := make(chan error, 2)

	halfCopy := func(dst, src net.Conn) {
		_, err := copyWithIdleTimeout(dst, src, global.IdleTimeout)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		errCh <- err
	}

	go halfCopy(*source, *target)
	go halfCopy(*target, *source)

	err1 := <-errCh
	err2 := <-errCh

	for _, err := range []error{err1, err2} {
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	}
	return nil
}

// copyWithIdleTimeout 类似 io.Copy，但在每次读取前设置读超时，
// 空闲超过 timeout 则返回超时错误。
func copyWithIdleTimeout(dst io.Writer, src io.Reader, timeout time.Duration) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		if timeout > 0 {
			if t, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
				t.SetReadDeadline(time.Now().Add(timeout))
			}
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			total += int64(nw)
			if ew != nil {
				return total, ew
			}
			if nr != nw {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}

func DialTcpConnection(address string) (net.Conn, error) {
	if global.ForwardRequired {
		switch global.ForwardConfig.Scheme {
		case global.Socks5:
			return forward.DialSocks5ProxyConnection(address)
		case global.HTTP:
			return forward.DialHTTPProxyConnection(address)
		default:
			return nil, errors.New("forward not supported yet")
		}
	} else {
		return net.DialTimeout("tcp", address, global.TcpConnectTimeout)
	}
}
