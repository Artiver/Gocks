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

// maxDatagramSize is the largest datagram that can be relayed: 65535 is the
// maximum UDP payload, so nothing is truncated.
const maxDatagramSize = 65535

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

	buffer := make([]byte, maxDatagramSize)
	for {
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

		// buffer is reused by the next ReadFrom, so the datagram is copied
		// before it is handed to its own goroutine.
		payload := make([]byte, size)
		copy(payload, buffer[:size])
		go handleRequest(payload, clientAddr, listen)
	}
}

func handleRequest(data []byte, clientAddr net.Addr, listen net.PacketConn) {
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

	if _, err := forwardConn.Write(data); err != nil {
		log.Printf("Failed to write to forward connection: %v", err)
		return
	}

	if err := forwardConn.SetReadDeadline(time.Now().Add(constant.UdpReceiveTimeout)); err != nil {
		return
	}

	responseBuffer := make([]byte, maxDatagramSize)
	n, err := forwardConn.Read(responseBuffer)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && !netErr.Timeout() {
			log.Printf("Failed to read from forward connection: %v", err)
		}
		return
	}

	if _, err := listen.WriteTo(responseBuffer[:n], clientAddr); err != nil {
		log.Printf("Failed to write to client connection: %v", err)
		return
	}

	log.Printf("[UDP] %s <-> %s", clientAddr, forwardConn.RemoteAddr())
}
