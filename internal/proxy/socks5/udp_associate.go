package socks5

import (
	"context"
	"gocks/internal/constant"
	"gocks/internal/dialer"
	socks5proto "gocks/internal/protocol/socks5"
	"log"
	"net"
	"sync"
	"time"
)

// udpBufferSize is large enough for any UDP payload plus the SOCKS5 header.
const udpBufferSize = 65535

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
	replyHost := bindIP.String()
	if bindIP.IsUnspecified() && ok && tcpLocal.IP != nil {
		replyHost = tcpLocal.IP.String()
	}
	if err := writeReply(conn, socks5proto.RepSucceeded, &socks5proto.Addr{
		Host: replyHost,
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

// udpSession is an upstream socket toward a single target, together with the
// client address replies are sent back to.
type udpSession struct {
	conn   *net.UDPConn
	client *net.UDPAddr
}

// clientPacket is one datagram received from the client, in both its raw and
// parsed form.
type clientPacket struct {
	wire  []byte
	dgram *socks5proto.UDPDatagram
	src   *net.UDPAddr
}

// udpRelay fans client datagrams out to per-target upstream sockets (direct)
// or to a single upstream SOCKS5 relay, and frames responses back to the
// client.
type udpRelay struct {
	clientConn *net.UDPConn
	clientIP   net.IP

	// upstreamConn is set when relaying through an upstream SOCKS5 proxy.
	upstreamConn *net.UDPConn

	mu         sync.Mutex
	clientAddr *net.UDPAddr
	sessions   map[string]*udpSession
}

func (r *udpRelay) run(ctx context.Context) {
	if r.upstreamConn != nil {
		r.runUpstream(ctx)
		return
	}
	r.runDirect(ctx)
}

func (r *udpRelay) runDirect(ctx context.Context) {
	defer r.closeAll()

	buf := make([]byte, udpBufferSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		packet, err := r.readClient(buf)
		if err != nil {
			return
		}
		if packet == nil {
			continue
		}

		target, err := net.ResolveUDPAddr("udp", packet.dgram.Header.Addr.String())
		if err != nil {
			log.Printf("[SOCKS5] [UDP] resolve %s: %v", packet.dgram.Header.Addr, err)
			continue
		}

		session := r.session(packet.src, target)
		if session == nil {
			continue
		}
		if _, err := session.conn.Write(packet.dgram.Data); err != nil {
			log.Printf("[SOCKS5] [UDP] forward to %s: %v", target, err)
		}
	}
}

// runUpstream relays whole SOCKS5 datagrams through a single upstream relay,
// which resolves and forwards them to the final targets. The client-provided
// header is preserved verbatim, so only the transport changes.
func (r *udpRelay) runUpstream(ctx context.Context) {
	go func() {
		<-ctx.Done()
		r.upstreamConn.Close()
	}()

	// upstream -> client
	go func() {
		ubuf := make([]byte, udpBufferSize)
		for {
			if err := r.upstreamConn.SetReadDeadline(time.Now().Add(constant.IdleTimeout)); err != nil {
				return
			}
			n, err := r.upstreamConn.Read(ubuf)
			if err != nil {
				return
			}
			r.mu.Lock()
			client := r.clientAddr
			r.mu.Unlock()
			if client == nil {
				continue
			}
			if _, err := r.clientConn.WriteToUDP(ubuf[:n], client); err != nil {
				return
			}
		}
	}()

	// client -> upstream
	buf := make([]byte, udpBufferSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		packet, err := r.readClient(buf)
		if err != nil {
			return
		}
		if packet == nil {
			continue
		}

		r.mu.Lock()
		r.clientAddr = packet.src
		r.mu.Unlock()

		if _, err := r.upstreamConn.Write(packet.wire); err != nil {
			return
		}
	}
}

// readClient waits for the next usable datagram from the client that owns the
// TCP control connection. A nil packet with a nil error means the datagram was
// ignored (wrong source address, malformed, or fragmented) and the caller
// should keep relaying; a non-nil error means the relay must stop. wire aliases
// buf.
func (r *udpRelay) readClient(buf []byte) (*clientPacket, error) {
	if err := r.clientConn.SetReadDeadline(time.Now().Add(constant.IdleTimeout)); err != nil {
		return nil, err
	}
	n, src, err := r.clientConn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	// RFC 1928 §7: only accept datagrams from the client that owns the TCP
	// control connection.
	if !src.IP.Equal(r.clientIP) {
		return nil, nil
	}

	dgram := &socks5proto.UDPDatagram{}
	if err := dgram.Unmarshal(buf[:n]); err != nil {
		log.Printf("[SOCKS5] [UDP] malformed datagram from %s: %v", src, err)
		return nil, nil
	}
	if dgram.Header.Frag != 0 {
		// Fragmentation is not supported.
		return nil, nil
	}
	return &clientPacket{wire: buf[:n], dgram: dgram, src: src}, nil
}

func (r *udpRelay) session(client, target *net.UDPAddr) *udpSession {
	key := target.String()

	r.mu.Lock()
	defer r.mu.Unlock()

	if s, ok := r.sessions[key]; ok {
		s.client = client
		return s
	}

	conn, err := net.DialUDP("udp", nil, target)
	if err != nil {
		log.Printf("[SOCKS5] [UDP] dial %s: %v", target, err)
		return nil
	}

	s := &udpSession{conn: conn, client: client}
	r.sessions[key] = s
	go r.pump(key, s, target)
	return s
}

// pump frames datagrams from a single upstream socket back to the client until
// the session goes idle or the upstream closes.
func (r *udpRelay) pump(key string, s *udpSession, target *net.UDPAddr) {
	defer func() {
		s.conn.Close()
		r.mu.Lock()
		delete(r.sessions, key)
		r.mu.Unlock()
	}()

	// Report the resolved upstream address, never a domain, so clients that
	// cannot parse ATYP=Domain (RFC 1928 §7) still work.
	srcAddr := &socks5proto.Addr{Host: target.IP.String(), Port: uint16(target.Port)}
	buf := make([]byte, udpBufferSize)
	for {
		if err := s.conn.SetReadDeadline(time.Now().Add(constant.IdleTimeout)); err != nil {
			return
		}
		n, err := s.conn.Read(buf)
		if err != nil {
			return
		}

		wire, err := socks5proto.NewUDPDatagram(
			socks5proto.NewUDPHeader(0, 0, srcAddr),
			buf[:n],
		).Marshal()
		if err != nil {
			return
		}

		r.mu.Lock()
		client := s.client
		r.mu.Unlock()

		if _, err := r.clientConn.WriteToUDP(wire, client); err != nil {
			return
		}
	}
}

func (r *udpRelay) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, s := range r.sessions {
		s.conn.Close()
		delete(r.sessions, key)
	}
}
