package socks5

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"gocks/internal/constant"
	"gocks/internal/dialer"
	socks5proto "gocks/internal/protocol/socks5"
	"gocks/internal/tunnel"
	"io"
	"log"
	"net"
	"strings"
	"syscall"
	"time"
)

func handleConnect(conn *net.Conn, addr *socks5proto.Addr) error {
	targetAddr := addr.String()
	targetConn, err := dialer.DialTcpConnection(targetAddr)

	if err != nil {
		if err1 := writeReply(conn, mapDialErrorToRep(err)); err1 != nil {
			return err1
		}
		return err
	}
	defer func(targetConn net.Conn) {
		err = targetConn.Close()
		if err != nil {
			log.Println("target connection close error", err)
		}
	}(targetConn)

	clientAddr := (*conn).RemoteAddr().String()
	log.Printf("[SOCKS5] [CONNECT] %s <--> %s", clientAddr, targetAddr)

	// RFC 1928 §6: report the address the server used to reach the target.
	if err := writeBndReply(conn, socks5proto.RepSucceeded, targetConn.LocalAddr()); err != nil {
		return err
	}

	return tunnel.TransportData(&targetConn, conn)
}

// mapDialErrorToRep maps a dial error to the closest SOCKS5 reply code.
func mapDialErrorToRep(err error) byte {
	if err == nil {
		return socks5proto.RepSucceeded
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return socks5proto.RepTTLExpired
	}

	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return socks5proto.RepConnRefused
	case errors.Is(err, syscall.EHOSTUNREACH):
		return socks5proto.RepHostUnreachable
	case errors.Is(err, syscall.ENETUNREACH):
		return socks5proto.RepNetUnreachable
	}

	// Fall back to the error text: the standard library dialer produces
	// stable, English, platform-independent messages for these cases.
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "refused"):
		return socks5proto.RepConnRefused
	case strings.Contains(s, "no route to host"):
		return socks5proto.RepHostUnreachable
	case strings.Contains(s, "unreachable"):
		return socks5proto.RepNetUnreachable
	case strings.Contains(s, "timeout"):
		return socks5proto.RepTTLExpired
	default:
		return socks5proto.RepFailure
	}
}

// bindWaitTimeout bounds how long BIND waits for the incoming connection.
const bindWaitTimeout = 2 * time.Minute

// errBindControlClosed signals that the client closed the control connection
// while BIND was waiting for the peer.
var errBindControlClosed = errors.New("bind: control connection closed")

func handleBind(conn *net.Conn, addr *socks5proto.Addr) error {
	listener, err := net.Listen(bindNetwork(addr), addr.String())
	if err != nil {
		if werr := writeReply(conn, socks5proto.RepFailure); werr != nil {
			return werr
		}
		return err
	}
	defer listener.Close()

	if tcpListener, ok := listener.(*net.TCPListener); ok {
		_ = tcpListener.SetDeadline(time.Now().Add(bindWaitTimeout))
	}

	// First reply: the address the client should tell the peer to connect to.
	if err := writeBindReply(*conn, bindAddr(listener, *conn)); err != nil {
		return err
	}

	clientAddr := (*conn).RemoteAddr().String()
	log.Printf("[SOCKS5] [BIND] %s listening on %s", clientAddr, listener.Addr())

	// Watch the control connection for an early client disconnect while the
	// peer is awaited. Peek never consumes, so any buffered data is relayed.
	br := bufio.NewReader(*conn)
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
		if !errors.Is(err, errBindControlClosed) {
			if werr := writeReply(conn, socks5proto.RepFailure); werr != nil {
				return werr
			}
		}
		return err
	}
	defer targetConn.Close()

	// Stop the watcher before relaying: bufio.Reader is not safe for
	// concurrent use, and we must reclaim the read deadline.
	if err := (*conn).SetReadDeadline(time.Now()); err != nil {
		return err
	}
	<-watcherDone
	if err := (*conn).SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	// Second reply: the address of the connecting peer (RFC 1928 §6).
	if err := writeBindReply(*conn, peerAddr(targetConn)); err != nil {
		return err
	}

	log.Printf("[SOCKS5] [BIND] %s <--> %s", clientAddr, targetConn.RemoteAddr())

	var wrapped net.Conn = tunnel.NewReaderConn(br, *conn)
	return tunnel.TransportData(&targetConn, &wrapped)
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

func writeBindReply(w net.Conn, addr *socks5proto.Addr) error {
	return socks5proto.NewReply(socks5proto.RepSucceeded, addr).Write(w)
}

type UDPHeader struct {
	Rsv      [2]byte
	Frag     byte
	AddrType byte
	DstAddr  []byte
	DstPort  uint16
}

func parseUDPHeader(buf *bytes.Buffer) (*UDPHeader, error) {
	var header UDPHeader
	var err error
	if _, err := io.ReadFull(buf, header.Rsv[:]); err != nil {
		return nil, err
	}

	header.Frag, err = buf.ReadByte()
	if err != nil {
		return nil, err
	}
	header.AddrType, err = buf.ReadByte()
	if err != nil {
		return nil, err
	}

	switch header.AddrType {
	case constant.AddrIPv4:
		header.DstAddr = make([]byte, net.IPv4len)
	case constant.AddrIPv6:
		header.DstAddr = make([]byte, net.IPv6len)
	case constant.AddrDomain:
		addrLen, err := buf.ReadByte()
		if err != nil {
			return nil, err
		}
		header.DstAddr = make([]byte, addrLen)
	default:
		return nil, errors.New("invalid address type")
	}

	if _, err := io.ReadFull(buf, header.DstAddr); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &header.DstPort); err != nil {
		return nil, err
	}

	return &header, nil
}

func handleUDPAssociate(conn *net.Conn) error {
	localAddr := &net.UDPAddr{
		IP:   (*conn).LocalAddr().(*net.TCPAddr).IP,
		Port: 0,
	}
	udpConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		(*conn).Write([]byte{constant.Socks5Version, 0x01})
		return err
	}
	defer udpConn.Close()

	log.Println("[SOCKS5] [UDP] start udp server", udpConn.LocalAddr())

	udpAddr := udpConn.LocalAddr().(*net.UDPAddr)
	resp := []byte{constant.Socks5Version, 0x00, 0x00, constant.AddrIPv4}
	resp = append(resp, udpAddr.IP.To4()...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(udpAddr.Port))
	resp = append(resp, portBytes...)
	if _, err := (*conn).Write(resp); err != nil {
		return err
	}

	buf := make([]byte, 65535)
	n, srcAddr, err := udpConn.ReadFromUDP(buf)
	if err != nil {
		return err
	}

	header, err := parseUDPHeader(bytes.NewBuffer(buf[:n]))
	if err != nil {
		return err
	}

	targetAddr := net.UDPAddr{
		IP:   net.IP(header.DstAddr),
		Port: int(header.DstPort),
	}
	if _, err := udpConn.WriteToUDP(buf[:n], &targetAddr); err != nil {
		return err
	}
	log.Printf("[SOCKS5] [UDP] %s -> %s\n", srcAddr, targetAddr.String())

	return nil
}
