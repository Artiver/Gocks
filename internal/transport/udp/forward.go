package udp

import (
	"context"
	"errors"
	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/netutil"
	"log"
	"net"
	"time"
)

// Run forwards UDP to the configured target until ctx is cancelled.
func Run(ctx context.Context) error {
	listen, err := net.ListenPacket("udp", config.ProxyConfig.BindAddr)
	if err != nil {
		return err
	}
	defer listen.Close()

	go func() {
		<-ctx.Done()
		listen.Close()
	}()

	log.Println("UDP port listening", config.ProxyConfig.BindAddr)

	for {
		buffer := make([]byte, constant.UdpReadBytes)
		size, clientAddr, err := listen.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("Failed to read from client connection: %v", err)
			if !netutil.Sleep(ctx, constant.AcceptBackoff) {
				return nil
			}
			continue
		}

		go handleRequest(buffer, size, clientAddr, listen)
	}
}

func handleRequest(data []byte, size int, clientAddr net.Addr, listen net.PacketConn) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	forwardConn, err := net.Dial("udp", config.ProxyConfig.TranAddr)
	if err != nil {
		log.Printf("Failed to forward to %s: %v", config.ProxyConfig.TranAddr, err)
		return
	}
	defer forwardConn.Close()

	_, err = forwardConn.Write(data[:size])
	if err != nil {
		log.Printf("Failed to write to forward connection: %v", err)
		return
	}

	err = forwardConn.SetReadDeadline(time.Now().Add(constant.UdpReceiveTimeout))
	if err != nil {
		return
	}

	responseBuffer := make([]byte, constant.UdpReadBytes)
	n, err := forwardConn.Read(responseBuffer)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && !netErr.Timeout() {
			log.Printf("Failed to read from forward connection: %v", err)
		}
		return
	}

	_, err = listen.WriteTo(responseBuffer[:n], clientAddr)
	if err != nil {
		log.Printf("Failed to write to client connection: %v", err)
		return
	}

	log.Printf("[UDP] %s <-> %s", clientAddr.String(), forwardConn.RemoteAddr().String())
}
