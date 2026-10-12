package tunnel

import (
	"context"
	"errors"
	"gocks/internal/constant"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// ErrNotSupported is returned by CloseWrite/CloseRead when the underlying
// connection does not support half-closing.
var ErrNotSupported = errors.New("tunnel: half-close not supported")

// ErrIdleTimeout is returned when a tunnel is closed because neither direction
// made progress for the whole IdleTimeout window.
var ErrIdleTimeout = errors.New("tunnel: idle timeout")

// TransportStats reports the bytes copied in each direction.
type TransportStats struct {
	SourceToTarget int64
	TargetToSource int64
}

// Count bytes
type result struct {
	dir int
	n   int64
	err error
}

// TransportData proxies data bidirectionally between source and target until
// both directions have finished.
func TransportData(source, target net.Conn) error {
	_, err := TransportDataStats(source, target)
	return err
}

// TransportDataStats is TransportData that also reports byte counts.
func TransportDataStats(source, target net.Conn) (TransportStats, error) {
	return TransportDataContextStats(context.Background(), source, target)
}

// TransportDataContextStats proxies data bidirectionally between source and
// target and reports byte counts. Each direction half-closes its destination
// when it ends, so the peer sees an EOF instead of a stalled connection. When
// a connection cannot be half-closed it is closed outright, which also
// unblocks the other direction. Cancelling ctx force-closes both connections.
func TransportDataContextStats(ctx context.Context, source, target net.Conn) (TransportStats, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// lastActivity is shared by both directions so the idle timer is measured
	// across the whole tunnel: progress on either side keeps the other side
	// alive. This matters for asymmetric flows like a large download, where the
	// client->target half is naturally silent for the entire transfer.
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	errCh := make(chan result, 2)
	go func() {
		n, err := copyHalf(ctx, target, source, &lastActivity)
		errCh <- result{1, n, err}
	}()
	go func() {
		n, err := copyHalf(ctx, source, target, &lastActivity)
		errCh <- result{0, n, err}
	}()

	var stats TransportStats
	var firstErr error
	completed := 0
	finish := func(r result) {
		if r.dir == 0 {
			stats.SourceToTarget = r.n
		} else {
			stats.TargetToSource = r.n
		}
		if firstErr == nil && !isBenign(r.err) {
			firstErr = r.err
		}
	}

	for completed < 2 {
		select {
		case r := <-errCh:
			completed++
			finish(r)
		case <-ctx.Done():
			forceClose(source, target)
			for completed < 2 {
				finish(<-errCh)
				completed++
			}
			if firstErr != nil {
				return stats, firstErr
			}
			return stats, ctx.Err()
		}
	}
	return stats, firstErr
}

// isBenign reports whether err is an expected result of a connection ending
// rather than a genuine transport failure.
func isBenign(err error) bool {
	return err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, ErrIdleTimeout)
}

// copyHalf copies src to dst until EOF or an error, then half-closes dst so
// the peer observes the end of this direction. It returns the bytes written.
// lastActivity is shared with the opposite direction: every successful read
// refreshes it, and the read deadline is computed from it, so progress on the
// peer side keeps this side alive even when it is itself idle.
func copyHalf(ctx context.Context, dst, src net.Conn, lastActivity *atomic.Int64) (int64, error) {
	defer func() {
		closeRead(src)
		closeWrite(dst)
	}()

	var total int64
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}

		if constant.IdleTimeout > 0 {
			if rd, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
				deadline := time.Unix(0, lastActivity.Load()).Add(constant.IdleTimeout)
				now := time.Now()
				if !deadline.After(now) {
					return total, ErrIdleTimeout
				}
				_ = rd.SetReadDeadline(deadline)
			}
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			lastActivity.Store(time.Now().UnixNano())
			nw, ew := dst.Write(buf[:nr])
			total += int64(nw)
			if ew != nil {
				return total, ew
			}
			if nw != nr {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return total, nil
			}
			// A read-deadline expiry may just mean the peer refreshed the
			// shared activity clock while we were blocked. Re-check and either
			// renew our deadline or declare the whole tunnel idle.
			if constant.IdleTimeout > 0 && isTimeoutErr(er) {
				deadline := time.Unix(0, lastActivity.Load()).Add(constant.IdleTimeout)
				if time.Now().Before(deadline) {
					continue
				}
				return total, ErrIdleTimeout
			}
			return total, er
		}
	}
}

// isTimeoutErr reports whether err is a network timeout (e.g. an expired read
// deadline) as opposed to a hard read failure.
func isTimeoutErr(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
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

func forceClose(conns ...net.Conn) {
	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
}
