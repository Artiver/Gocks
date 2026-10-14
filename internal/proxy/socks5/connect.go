package socks5

import (
	"errors"
	"gocks/internal/dialer"
	"gocks/internal/netutil"
	socks5proto "gocks/internal/protocol/socks5"
	"gocks/internal/tunnel"
	"log"
	"net"
	"strings"
	"syscall"
	"time"
)

func handleConnect(conn net.Conn, addr *socks5proto.Addr) error {
	targetAddr := addr.String()
	targetConn, err := dialer.DialTcpConnection(targetAddr)

	if err != nil {
		if err1 := writeReply(conn, mapDialErrorToRep(err), nil); err1 != nil {
			return err1
		}
		return err
	}
	defer func(targetConn net.Conn) {
		err = targetConn.Close()
		if err != nil {
			log.Println("target connection close error", err)
		}
	}(targetConn)

	clientAddr := conn.RemoteAddr().String()
	log.Printf("[SOCKS5] [CONNECT] %s <--> %s", clientAddr, targetAddr)

	// RFC 1928 §6: report the address the server used to reach the target.
	if err := writeBndReply(conn, socks5proto.RepSucceeded, targetConn.LocalAddr()); err != nil {
		return err
	}

	start := time.Now()
	stats, err := tunnel.TransportDataStats(targetConn, conn)
	log.Printf("[SOCKS5] [CONNECT] %s <-> %s closed after %s (%d sent, %d received)",
		clientAddr, targetAddr, time.Since(start).Round(time.Millisecond), netutil.FormatBytes(stats.SourceToTarget), netutil.FormatBytes(stats.TargetToSource))
	return err
}

// mapDialErrorToRep maps a dial error to the closest SOCKS5 reply code.
func mapDialErrorToRep(err error) byte {
	if err == nil {
		return socks5proto.RepSucceeded
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return socks5proto.RepTTLExpired
	}

	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return socks5proto.RepConnRefused
	case errors.Is(err, syscall.EHOSTUNREACH):
		return socks5proto.RepHostUnreachable
	case errors.Is(err, syscall.ENETUNREACH):
		return socks5proto.RepNetUnreachable
	}

	// Fall back to the error text: the standard library dialer produces
	// stable, English, platform-independent messages for these cases.
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "refused"):
		return socks5proto.RepConnRefused
	case strings.Contains(s, "no route to host"):
		return socks5proto.RepHostUnreachable
	case strings.Contains(s, "unreachable"):
		return socks5proto.RepNetUnreachable
	case strings.Contains(s, "timeout"):
		return socks5proto.RepTTLExpired
	default:
		return socks5proto.RepFailure
	}
}
