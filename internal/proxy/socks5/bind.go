package socks5

import (
	"bufio"
	"errors"
	"gocks/internal/netutil"
	socks5proto "gocks/internal/protocol/socks5"
	"gocks/internal/tunnel"
	"log"
	"net"
	"time"
)

// bindWaitTimeout bounds how long BIND waits for the incoming connection.
const bindWaitTimeout = 2 * time.Minute

// errBindControlClosed signals that the client closed the control connection
// while BIND was waiting for the peer.
var errBindControlClosed = errors.New("bind: control connection closed")

func handleBind(conn net.Conn, addr *socks5proto.Addr) error {
	listener, err := net.Listen(bindNetwork(addr), addr.String())
	if err != nil {
		return failReply(conn, err)
	}
	defer listener.Close()

	if tcpListener, ok := listener.(*net.TCPListener); ok {
		_ = tcpListener.SetDeadline(time.Now().Add(bindWaitTimeout))
	}

	// First reply: the address the client should tell the peer to connect to.
	if err := writeReply(conn, socks5proto.RepSucceeded, bindAddr(listener, conn)); err != nil {
		return err
	}

	clientAddr := conn.RemoteAddr().String()
	log.Printf("[SOCKS5] [BIND] %s listening on %s", clientAddr, listener.Addr())

	// Watch the control connection for an early client disconnect while the
	// peer is awaited. Peek never consumes, so any buffered data is relayed.
	br := bufio.NewReader(conn)
	controlClosed := make(chan error, 1)
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		_, err := br.Peek(1)
		controlClosed <- err
	}()

	acceptCh := make(chan net.Conn, 1)
	acceptErrCh := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			acceptErrCh <- err
			return
		}
		acceptCh <- c
	}()

	targetConn, err := waitForPeer(listener, acceptCh, acceptErrCh, controlClosed)
	if err != nil {
		if errors.Is(err, errBindControlClosed) {
			return err
		}
		return failReply(conn, err)
	}
	defer targetConn.Close()

	// Stop the watcher before relaying: bufio.Reader is not safe for
	// concurrent use, and we must reclaim the read deadline.
	if err := conn.SetReadDeadline(time.Now()); err != nil {
		return err
	}
	<-watcherDone
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	// Second reply: the address of the connecting peer (RFC 1928 §6).
	if err := writeReply(conn, socks5proto.RepSucceeded, peerAddr(targetConn)); err != nil {
		return err
	}

	log.Printf("[SOCKS5] [BIND] %s <--> %s", clientAddr, targetConn.RemoteAddr())

	start := time.Now()
	stats, err := tunnel.TransportDataStats(targetConn, tunnel.NewReaderConn(br, conn))
	log.Printf("[SOCKS5] [BIND] %s <-> %s closed after %s (%s sent, %s received)",
		clientAddr, targetConn.RemoteAddr(), time.Since(start).Round(time.Millisecond), netutil.FormatBytes(stats.SourceToTarget), netutil.FormatBytes(stats.TargetToSource))
	return err
}

// waitForPeer waits until a peer connects, the client disconnects, or the
// listener deadline expires.
func waitForPeer(listener net.Listener, acceptCh <-chan net.Conn, acceptErrCh <-chan error, controlClosed <-chan error) (net.Conn, error) {
	for {
		select {
		case c := <-acceptCh:
			return c, nil
		case err := <-acceptErrCh:
			return nil, err
		case err := <-controlClosed:
			if err != nil {
				listener.Close()
				if c := drainConn(acceptCh); c != nil {
					c.Close()
				}
				return nil, errBindControlClosed
			}
			// Early client data was buffered; stop monitoring and keep
			// waiting for the peer.
			controlClosed = nil
		}
	}
}

func drainConn(ch <-chan net.Conn) net.Conn {
	select {
	case c := <-ch:
		return c
	default:
		return nil
	}
}

// bindNetwork picks a single-stack network so the listener does not end up on
// a dual-stack wildcard address.
func bindNetwork(addr *socks5proto.Addr) string {
	switch addr.Type {
	case socks5proto.AddrIPv4:
		return "tcp4"
	case socks5proto.AddrIPv6:
		return "tcp6"
	default:
		return "tcp"
	}
}

// bindAddr is the address reported in the first BIND reply: the listener port
// on the interface the client already reached us on.
func bindAddr(listener net.Listener, conn net.Conn) *socks5proto.Addr {
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	host := tcpAddr.IP.String()
	if local, ok := conn.LocalAddr().(*net.TCPAddr); ok && local.IP != nil && !local.IP.IsUnspecified() {
		host = local.IP.String()
	}
	return &socks5proto.Addr{Host: host, Port: uint16(tcpAddr.Port)}
}

// peerAddr is the address reported in the second BIND reply.
func peerAddr(conn net.Conn) *socks5proto.Addr {
	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	return &socks5proto.Addr{Host: tcpAddr.IP.String(), Port: uint16(tcpAddr.Port)}
}
