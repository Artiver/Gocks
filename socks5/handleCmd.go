package socks5

import (
	"Gocks/utils"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
)

func handleConnect(conn *net.Conn, targetAddr string) error {
	targetConn, err := utils.DialTcpConnection(targetAddr)

	// The server evaluates the request, and returns a reply formed as follows:
	//
	//    +----+-----+-------+------+----------+----------+
	//    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	//    +----+-----+-------+------+----------+----------+
	//    | 1  |  1  | X'00' |  1   | Variable |    2     |
	//    +----+-----+-------+------+----------+----------+

	if err != nil {
		_, err = (*conn).Write(connectFailed)
		if err != nil {
			return err
		}
		return errors.New("dial tcp " + targetAddr)
	}
	defer func(targetConn net.Conn) {
		err = targetConn.Close()
		if err != nil {
			log.Println("target connection close error", err)
		}
	}(targetConn)

	clientAddr := (*conn).RemoteAddr().String()
	log.Printf("[SOCKS5] [CONNECT] %s <--> %s", clientAddr, targetAddr)

	_, err = (*conn).Write(connectSuccess)
	if err != nil {
		return err
	}

	return utils.TransportData(&targetConn, conn)
}

func handleBind(conn *net.Conn, targetAddr string) error {
	listener, err := net.Listen("tcp", targetAddr)
	if err != nil {
		(*conn).Write(connectRefused)
		return err
	}
	defer listener.Close()

	localAddr := listener.Addr().(*net.TCPAddr)
	resp := []byte{socks5Version, 0, 0, addrIPv4}
	resp = append(resp, localAddr.IP.To4()...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(localAddr.Port))
	resp = append(resp, portBuf...)
	if _, err = (*conn).Write(resp); err != nil {
		return err
	}

	targetConn, err := listener.Accept()
	if err != nil {
		(*conn).Write(connectFailed)
		return err
	}
	defer targetConn.Close()

	resp = []byte{socks5Version, 0, 0, addrIPv4}
	resp = append(resp, localAddr.IP.To4()...)
	binary.BigEndian.PutUint16(portBuf, uint16(localAddr.Port))
	resp = append(resp, portBuf...)
	if _, err = (*conn).Write(resp); err != nil {
		return err
	}

	clientAddr := (*conn).RemoteAddr().String()
	log.Printf("[SOCKS5] [BIND] %s <--> %s", clientAddr, targetAddr)

	return utils.TransportData(&targetConn, conn)
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
	if _, err := io.ReadFull(buf, header.Rsv[:]); err != nil {
		return nil, err
	}

	header.Frag, _ = buf.ReadByte()
	header.AddrType, _ = buf.ReadByte()

	switch header.AddrType {
	case addrIPv4:
		header.DstAddr = make([]byte, net.IPv4len)
	case addrIPv6:
		header.DstAddr = make([]byte, net.IPv6len)
	case addrDomain:
		addrLen, _ := buf.ReadByte()
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
	// Create a UDP server to handle incoming requests
	localAddr := &net.UDPAddr{
		IP:   (*conn).LocalAddr().(*net.TCPAddr).IP,
		Port: 0,
	}
	udpConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		(*conn).Write([]byte{socks5Version, 0x01})
		return err
	}
	defer udpConn.Close()

	log.Println("[SOCKS5] [UDP] start udp server", udpConn.LocalAddr())

	// Respond with the local address of the UDP server
	udpAddr := udpConn.LocalAddr().(*net.UDPAddr)
	resp := []byte{socks5Version, 0x00, 0x00, addrIPv4}
	resp = append(resp, udpAddr.IP.To4()...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(udpAddr.Port))
	resp = append(resp, portBytes...)
	(*conn).Write(resp)

	// Read and forward UDP packets
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
	udpConn.WriteToUDP(buf[len(buf)-n:], &targetAddr)
	log.Printf("[SOCKS5] [UDP] %s -> %s\n", srcAddr, targetAddr.String())

	return nil
}
