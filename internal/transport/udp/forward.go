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

// udpReceiveTimeout bounds how long to wait for the upstream reply.
const udpReceiveTimeout = 3 * time.Second

// Run forwards UDP to the configured target until ctx is cancelled.
func Run(ctx context.Context, cfg config.Config) error {
	listen, err := net.ListenPacket("udp", cfg.Listen.Addr)
	if err != nil {
		return err
	}
	defer listen.Close()

	go func() {
		<-ctx.Done()
		listen.Close()
	}()

	log.Println("UDP port listening", cfg.Listen.Addr)

	buffer := make([]byte, constant.UDPBufferSize)
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
		go handleRequest(payload, clientAddr, listen, cfg.Listen.Target)
	}
}

func handleRequest(data []byte, clientAddr net.Addr, listen net.PacketConn, target string) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	forwardConn, err := net.Dial("udp", target)
	if err != nil {
		log.Printf("Failed to forward to %s: %v", target, err)
		return
	}
	defer forwardConn.Close()

	if _, err := forwardConn.Write(data); err != nil {
		log.Printf("Failed to write to forward connection: %v", err)
		return
	}

	if err := forwardConn.SetReadDeadline(time.Now().Add(udpReceiveTimeout)); err != nil {
		return
	}

	responseBuffer := make([]byte, constant.UDPBufferSize)
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
