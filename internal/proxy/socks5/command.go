package socks5

import (
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

func handleBind(conn *net.Conn, addr *socks5proto.Addr) error {
	targetAddr := addr.String()
	listener, err := net.Listen("tcp", targetAddr)
	if err != nil {
		if werr := writeReply(conn, socks5proto.RepFailure); werr != nil {
			return werr
		}
		return err
	}
	defer listener.Close()

	localAddr := listener.Addr().(*net.TCPAddr)
	resp := []byte{constant.Socks5Version, 0, 0, constant.AddrIPv4}
	resp = append(resp, localAddr.IP.To4()...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(localAddr.Port))
	resp = append(resp, portBuf...)
	if _, err = (*conn).Write(resp); err != nil {
		return err
	}

	targetConn, err := listener.Accept()
	if err != nil {
		if werr := writeReply(conn, socks5proto.RepFailure); werr != nil {
			return werr
		}
		return err
	}
	defer targetConn.Close()

	resp = []byte{constant.Socks5Version, 0, 0, constant.AddrIPv4}
	resp = append(resp, localAddr.IP.To4()...)
	binary.BigEndian.PutUint16(portBuf, uint16(localAddr.Port))
	resp = append(resp, portBuf...)
	if _, err = (*conn).Write(resp); err != nil {
		return err
	}

	clientAddr := (*conn).RemoteAddr().String()
	log.Printf("[SOCKS5] [BIND] %s <--> %s", clientAddr, targetAddr)

	return tunnel.TransportData(&targetConn, conn)
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
