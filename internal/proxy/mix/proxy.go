package mix

import (
	"context"
	"gocks/internal/config"
	"gocks/internal/constant"
	socks5proto "gocks/internal/protocol/socks5"
	"gocks/internal/proxy/http"
	"gocks/internal/proxy/socks5"
	"gocks/internal/server"
	"log"
	"net"
	"time"
)

// defaultReadBytes is the prefix the mixed-mode dispatcher reads to tell HTTP
// and SOCKS5 apart.
const defaultReadBytes = 512

// Run serves the HTTP+SOCKS5 mixed proxy until ctx is cancelled.
func Run(ctx context.Context, cfg config.Config) error {
	httpProxy := http.New(cfg)
	socks5Proxy := socks5.New(cfg)
	return server.Serve(ctx, "HTTP+SOCKS5 proxy", cfg.Listen.Addr, func(conn net.Conn) {
		chooseProxy(conn, httpProxy, socks5Proxy)
	})
}

// chooseProxy peeks at the first byte to tell the two protocols apart: a SOCKS5
// client always opens with its version byte, anything else is treated as HTTP.
// The pre-read bytes are handed to the chosen handler so its parser sees the
// complete opening message.
func chooseProxy(conn net.Conn, httpProxy *http.Proxy, socks5Proxy *socks5.Proxy) {
	buff := make([]byte, defaultReadBytes)
	if err := conn.SetReadDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		log.Printf("set read deadline error: %v", err)
		conn.Close()
		return
	}
	n, err := conn.Read(buff)
	if err != nil || n < 1 {
		log.Printf("Error reading from connection: %v", err)
		conn.Close()
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("reset read deadline error: %v", err)
		conn.Close()
		return
	}

	if buff[0] == socks5proto.Version {
		socks5Proxy.HandleConnection(conn, buff[:n])
		return
	}
	httpProxy.HandleConnection(conn, buff[:n])
}
