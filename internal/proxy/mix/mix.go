package mix

import (
	"context"
	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/netutil"
	"gocks/internal/proxy/http"
	"gocks/internal/proxy/socks5"
	"log"
	"net"
	"time"
)

// Run serves the HTTP+SOCKS5 mixed proxy until ctx is cancelled.
func Run(ctx context.Context) error {
	listen, err := net.Listen("tcp", config.ProxyConfig.BindAddr)
	if err != nil {
		return err
	}
	defer listen.Close()

	go func() {
		<-ctx.Done()
		listen.Close()
	}()

	log.Println("MIX proxy listening", config.ProxyConfig.BindAddr)

	for {
		conn, err := listen.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Println("Error accepting connection:", err)
			if !netutil.Sleep(ctx, constant.AcceptBackoff) {
				return nil
			}
			continue
		}
		go chooseProxy(&conn)
	}
}

func chooseProxy(conn *net.Conn) {
	buff := make([]byte, constant.DefaultReadBytes)
	if err := (*conn).SetReadDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		log.Printf("set read deadline error: %v", err)
		return
	}
	n, err := (*conn).Read(buff)
	if err != nil || n < 1 {
		log.Printf("Error reading from connection: %v", err)
		return
	}
	if err := (*conn).SetReadDeadline(time.Time{}); err != nil {
		log.Printf("reset read deadline error: %v", err)
		return
	}

	switch buff[0] {
	case 0x05:
		go socks5.HandleSocks5Connection(conn, buff[:n])
	default:
		go http.HandleHTTPConnection(conn, buff[:n])
	}
}
