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

// Run serves the HTTP+SOCKS5 mixed proxy until ctx is cancelled.
func Run(ctx context.Context) error {
	return server.Serve(ctx, "MIX proxy", config.ProxyConfig.BindAddr, chooseProxy)
}

// chooseProxy peeks at the first byte to tell the two protocols apart: a SOCKS5
// client always opens with its version byte, anything else is treated as HTTP.
// The pre-read bytes are handed to the chosen handler so its parser sees the
// complete opening message.
func chooseProxy(conn net.Conn) {
	buff := make([]byte, constant.DefaultReadBytes)
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
		socks5.HandleSocks5Connection(conn, buff[:n])
		return
	}
	http.HandleHTTPConnection(conn, buff[:n])
}
