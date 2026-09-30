package tunnel

import (
	"context"
	"errors"
	"fmt"
	"gocks/internal/constant"
	"io"
	"net"
	"strings"
	"time"
)

// ErrNotSupported is returned by CloseWrite/CloseRead when the underlying
// connection does not support half-closing.
var ErrNotSupported = errors.New("tunnel: half-close not supported")

func FormatAddress(ip string, port uint16) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// TransportData proxies data bidirectionally between source and target until
// both directions have finished. It is TransportDataContext with a background
// context.
func TransportData(source, target *net.Conn) error {
	return TransportDataContext(context.Background(), source, target)
}

// TransportDataContext proxies data bidirectionally between source and target.
// Each direction half-closes its destination when it ends, so the peer sees an
// EOF instead of a stalled connection. When a connection cannot be
// half-closed it is closed outright, which also unblocks the other direction.
// Cancelling ctx force-closes both connections.
func TransportDataContext(ctx context.Context, source, target *net.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	go func() { errCh <- copyHalf(ctx, *target, *source) }()
	go func() { errCh <- copyHalf(ctx, *source, *target) }()

	var firstErr error
	completed := 0
	for completed < 2 {
		select {
		case err := <-errCh:
			completed++
			if firstErr == nil && !isBenign(err) {
				firstErr = err
			}
		case <-ctx.Done():
			forceClose(source, target)
			for completed < 2 {
				err := <-errCh
				completed++
				if firstErr == nil && !isBenign(err) {
					firstErr = err
				}
			}
			if firstErr != nil {
				return firstErr
			}
			return ctx.Err()
		}
	}
	return firstErr
}

// isBenign reports whether err is an expected result of a connection ending
// rather than a genuine transport failure.
func isBenign(err error) bool {
	return err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled)
}

// copyHalf copies src to dst until EOF or an error, then half-closes dst so
// the peer observes the end of this direction.
func copyHalf(ctx context.Context, dst, src net.Conn) error {
	defer func() {
		closeRead(src)
		closeWrite(dst)
	}()

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if constant.IdleTimeout > 0 {
			if rd, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
				_ = rd.SetReadDeadline(time.Now().Add(constant.IdleTimeout))
			}
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if ew != nil {
				return ew
			}
			if nw != nr {
				return io.ErrShortWrite
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return nil
			}
			return er
		}
	}
}

// closeWrite half-closes the write side of c. Connections that cannot be
// half-closed are closed outright, which unblocks the peer's pending read.
func closeWrite(c net.Conn) {
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		_ = c.Close()
		return
	}
	if err := cw.CloseWrite(); err != nil {
		_ = c.Close()
	}
}

// closeRead half-closes the read side of c when supported.
func closeRead(c net.Conn) {
	if cr, ok := c.(interface{ CloseRead() error }); ok {
		_ = cr.CloseRead()
	}
}

func forceClose(conns ...*net.Conn) {
	for _, c := range conns {
		if c != nil && *c != nil {
			_ = (*c).Close()
		}
	}
}
