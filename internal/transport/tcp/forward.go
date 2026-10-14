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

// Run forwards TCP to the configured target until ctx is cancelled.
func Run(ctx context.Context) error {
	return server.Serve(ctx, "TCP port", config.ProxyConfig.BindAddr, handleConnection)
}

func handleConnection(src net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	defer src.Close()

	// Dial through the configured upstream chain, exactly like the proxies do,
	// so -F applies to port forwarding as well.
	dst, err := dialer.DialTcpConnection(config.ProxyConfig.TranAddr)
	if err != nil {
		log.Println("dial tcp error which", config.ProxyConfig.TranAddr)
		return
	}
	defer dst.Close()

	log.Printf("[TCP] %s <-> %s", src.RemoteAddr(), dst.RemoteAddr())

	start := time.Now()
	stats, err := tunnel.TransportDataStats(src, dst)
	log.Printf("[TCP] %s <-> %s closed after %s (%s sent, %s received)",
		src.RemoteAddr(), dst.RemoteAddr(), time.Since(start).Round(time.Millisecond), netutil.FormatBytes(stats.SourceToTarget), netutil.FormatBytes(stats.TargetToSource))
	if err != nil {
		log.Println("transport data error", err)
	}
}
