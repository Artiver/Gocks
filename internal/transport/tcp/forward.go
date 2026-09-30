package tcp

import (
	"context"
	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/netutil"
	"gocks/internal/tunnel"
	"log"
	"net"
)

// Run forwards TCP to the configured target until ctx is cancelled.
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

	log.Println("TCP port listening", config.ProxyConfig.BindAddr)

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

		go handleConnection(&conn)
	}
}

func handleConnection(src *net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	dst, err := net.DialTimeout("tcp", config.ProxyConfig.TranAddr, constant.TcpConnectTimeout)
	defer (*src).Close()

	if err != nil {
		log.Println("dial tcp error which", config.ProxyConfig.TranAddr)
		return
	}
	defer dst.Close()

	err = tunnel.TransportData(src, &dst)
	if err != nil {
		log.Println("transport data error", err)
	}

	log.Printf("[TCP] %s <-> %s", (*src).RemoteAddr().String(), dst.RemoteAddr().String())
}
