package socks5

import (
	"context"
	"gocks/internal/dialer"
	socks5proto "gocks/internal/protocol/socks5"
	"log"
	"net"
)

// handleUDPAssociate implements RFC 1928 §7: it binds a client-facing UDP
// socket and relays datagrams between the client and one upstream socket per
// target, until the TCP control connection closes or the relay goes idle.
func handleUDPAssociate(conn net.Conn) error {
	// Bind on the interface the client reached us on so that replies carry a
	// source address the client will accept (RFC 1928 §6).
	tcpLocal, ok := conn.LocalAddr().(*net.TCPAddr)
	bindIP := net.IPv4zero
	if ok && tcpLocal.IP != nil {
		bindIP = tcpLocal.IP
	}

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP})
	if err != nil {
		return failReply(conn, err)
	}
	defer clientConn.Close()

	// Optionally chain the association through an upstream SOCKS5 proxy.
	// This happens before the success reply so a failure is reported properly.
	control, relayAddr, err := dialer.DialUdpAssociation()
	if err != nil {
		return failReply(conn, err)
	}
	var upstreamConn *net.UDPConn
	if control != nil {
		defer control.Close()

		upAddr, err := net.ResolveUDPAddr("udp", relayAddr.String())
		if err != nil {
			return failReply(conn, err)
		}
		upstreamConn, err = net.DialUDP("udp", nil, upAddr)
		if err != nil {
			return failReply(conn, err)
		}
		defer upstreamConn.Close()
	}

	bound := clientConn.LocalAddr().(*net.UDPAddr)
	if err := writeReply(conn, socks5proto.RepSucceeded, &socks5proto.Addr{
		Host: bindIP.String(),
		Port: uint16(bound.Port),
	}); err != nil {
		return err
	}

	clientIP := net.IPv4zero
	if remote, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = remote.IP
	}
	if upstreamConn != nil {
		log.Printf("[SOCKS5] [UDP] %s relay on %s via upstream %s",
			conn.RemoteAddr(), bound, upstreamConn.RemoteAddr())
	} else {
		log.Printf("[SOCKS5] [UDP] %s relay on %s", conn.RemoteAddr(), bound)
	}

	// The association lives as long as the TCP control connection.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		var b [1]byte
		for {
			if _, err := conn.Read(b[:]); err != nil {
				cancel()
				return
			}
		}
	}()
	// Unblock the relay's client reader on teardown.
	go func() {
		<-ctx.Done()
		clientConn.Close()
	}()

	r := &udpRelay{
		clientConn:   clientConn,
		clientIP:     clientIP,
		upstreamConn: upstreamConn,
		sessions:     make(map[string]*udpSession),
	}
	r.run(ctx)
	return nil
}
