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

// ServePacket forwards UDP to rule's target on pc until ctx is cancelled.
func ServePacket(ctx context.Context, rule config.Rule, pc net.PacketConn) error {
	logger := rule.Logger()

	done := make(chan struct{})
	defer close(done)
	defer pc.Close()
	go func() {
		select {
		case <-ctx.Done():
			pc.Close()
		case <-done:
		}
	}()

	logger.Println("UDP port listening", rule.Listen.Addr)

	buffer := make([]byte, constant.UDPBufferSize)
	for {
		size, clientAddr, err := pc.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Printf("Failed to read from client connection: %v", err)
			if !netutil.Sleep(ctx, constant.AcceptBackoff) {
				return nil
			}
			continue
		}

		// buffer is reused by the next ReadFrom, so the datagram is copied
		// before it is handed to its own goroutine.
		payload := make([]byte, size)
		copy(payload, buffer[:size])
		go handleRequest(payload, clientAddr, pc, rule.Listen.Target, logger)
	}
}

func handleRequest(data []byte, clientAddr net.Addr, listen net.PacketConn, target string, logger *log.Logger) {
	defer func() {
		if err := recover(); err != nil {
			logger.Println(err)
		}
	}()
	forwardConn, err := net.Dial("udp", target)
	if err != nil {
		logger.Printf("Failed to forward to %s: %v", target, err)
		return
	}
	defer forwardConn.Close()

	if _, err := forwardConn.Write(data); err != nil {
		logger.Printf("Failed to write to forward connection: %v", err)
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
			logger.Printf("Failed to read from forward connection: %v", err)
		}
		return
	}

	if _, err := listen.WriteTo(responseBuffer[:n], clientAddr); err != nil {
		logger.Printf("Failed to write to client connection: %v", err)
		return
	}

	logger.Printf("[UDP] %s <-> %s", clientAddr, forwardConn.RemoteAddr())
}
