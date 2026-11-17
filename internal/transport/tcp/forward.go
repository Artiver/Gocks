package tcp

import (
	"context"
	"gocks/internal/config"
	"gocks/internal/dialer"
	"gocks/internal/netutil"
	"gocks/internal/server"
	"gocks/internal/tunnel"
	"log"
	"net"
	"time"
)

// Serve forwards TCP to rule's target on ln until ctx is cancelled.
func Serve(ctx context.Context, rule config.Rule, ln net.Listener) error {
	d := dialer.New(rule.Upstream)
	logger := rule.Logger()
	return server.ServeListener(ctx, rule.LogPrefix("TCP port"), ln, func(conn net.Conn) {
		handleConnection(conn, d, rule.Listen.Target, rule.Timeout, logger)
	})
}

func handleConnection(src net.Conn, d *dialer.Dialer, target string, timeout time.Duration, logger *log.Logger) {
	defer func() {
		if err := recover(); err != nil {
			logger.Println(err)
		}
	}()
	defer src.Close()

	// Dial through the configured upstream chain, exactly like the proxies do,
	// so -F applies to port forwarding as well.
	dst, err := d.DialTCP(target)
	if err != nil {
		logger.Printf("dial tcp %s: %v", target, err)
		return
	}
	defer dst.Close()

	logger.Printf("[TCP] %s <-> %s", src.RemoteAddr(), dst.RemoteAddr())

	start := time.Now()
	stats, err := tunnel.TransportDataStats(timeout, src, dst)
	logger.Printf("[TCP] %s <-> %s closed after %s (%s sent, %s received)",
		src.RemoteAddr(), dst.RemoteAddr(), time.Since(start).Round(time.Millisecond), netutil.FormatBytes(stats.SourceToTarget), netutil.FormatBytes(stats.TargetToSource))
	if err != nil {
		logger.Println("transport data error", err)
	}
}
