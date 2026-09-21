package tunnel

import (
	"errors"
	"fmt"
	"gocks/internal/constant"
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

func TransportData(source, target *net.Conn) error {
	errCh := make(chan error, 2)

	halfCopy := func(dst, src net.Conn) {
		_, err := copyWithIdleTimeout(dst, src, constant.IdleTimeout)
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
