package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"gocks/internal/constant"
	"gocks/internal/dialer"
	"gocks/internal/tunnel"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

func handleConnect(conn *net.Conn, targetAddr string) error {
	targetConn, err := dialer.DialTcpConnection(targetAddr)
	if err != nil {
		rep := mapDialErrorToRep(err)
		if _, err1 := (*conn).Write(buildFailureResponse(rep)); err1 != nil {
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

	if _, err := (*conn).Write(constant.ConnectSuccess); err != nil {
		return err
	}

	return tunnel.TransportData(&targetConn, conn)
}

func buildFailureResponse(rep byte) []byte {
	return []byte{constant.Socks5Version, rep, 0x00, constant.AddrIPv4, 0, 0, 0, 0, 0, 0}
}

func mapDialErrorToRep(err error) byte {
	if err == nil {
		return 0x00
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return 0x06
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout"):
		return 0x06
	case strings.Contains(s, "refused"):
		return 0x05
	case strings.Contains(s, "unreachable"):
		return 0x03
	case strings.Contains(s, "no route"):
		return 0x04
	default:
		return 0x01
	}
}

func handleBind(conn *net.Conn, targetAddr string) error {
	expectedHost, _, _ := net.SplitHostPort(targetAddr)

	listenAddr := ":0"
	localIP := (*conn).LocalAddr().(*net.TCPAddr).IP
	if localIP != nil && !localIP.IsUnspecified() {
		listenAddr = net.JoinHostPort(localIP.String(), "0")
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		if _, werr := (*conn).Write(buildFailureResponse(0x01)); werr != nil {
			return werr
		}
		return err
	}
	defer listener.Close()

	if err := writeBindResponse(*conn, listener.Addr()); err != nil {
		return err
	}

	tcpListener, ok := listener.(*net.TCPListener)
	if ok {
		_ = tcpListener.SetDeadline(time.Now().Add(constant.BindWaitTimeout))
	}
	targetConn, err := listener.Accept()
	if err != nil {
		if _, werr := (*conn).Write(buildFailureResponse(0x01)); werr != nil {
			return werr
		}
		return err
	}
	defer targetConn.Close()

	if expectedHost != "" && expectedHost != "0.0.0.0" && expectedHost != "::" {
		remoteHost, _, _ := net.SplitHostPort(targetConn.RemoteAddr().String())
		if remoteHost != expectedHost {
			_ = targetConn.Close()
			if _, werr := (*conn).Write(buildFailureResponse(0x01)); werr != nil {
				return werr
			}
			return errors.New("bind: unauthorized incoming connection")
		}
	}

	if err := writeBindResponse(*conn, targetConn.LocalAddr()); err != nil {
		return err
	}

	clientAddr := (*conn).RemoteAddr().String()
	log.Printf("[SOCKS5] [BIND] %s <--> %s", clientAddr, targetConn.RemoteAddr().String())

	return tunnel.TransportData(&targetConn, conn)
}

func writeBindResponse(conn net.Conn, addr net.Addr) error {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return errors.New("bind: invalid address type")
	}
	resp := []byte{constant.Socks5Version, 0x00, 0x00}
	if ip4 := tcpAddr.IP.To4(); ip4 != nil {
		resp = append(resp, constant.AddrIPv4)
		resp = append(resp, ip4...)
	} else {
		resp = append(resp, constant.AddrIPv6)
		resp = append(resp, tcpAddr.IP.To16()...)
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(tcpAddr.Port))
	resp = append(resp, portBuf...)
	_, err := conn.Write(resp)
	return err
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

type udpSession struct {
	targetConn *net.UDPConn
	clientAddr *net.UDPAddr
}

func handleUDPAssociate(conn *net.Conn) error {
	localAddr := &net.UDPAddr{
		IP:   (*conn).LocalAddr().(*net.TCPAddr).IP,
		Port: 0,
	}
	udpConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		_, _ = (*conn).Write(buildFailureResponse(0x01))
		return err
	}
	defer udpConn.Close()

	if err := writeUDPAssociateResponse(*conn, udpConn.LocalAddr()); err != nil {
		return err
	}

	log.Println("[SOCKS5] [UDP] listening", udpConn.LocalAddr())

	var sessions sync.Map
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		sessions.Range(func(_, v interface{}) bool {
			_ = v.(*udpSession).targetConn.Close()
			return true
		})
	}()

	go func() {
		buf := make([]byte, 1)
		_, _ = (*conn).Read(buf)
		cancel()
	}()

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if err := udpConn.SetReadDeadline(time.Now().Add(constant.IdleTimeout)); err != nil {
			return err
		}
		n, srcAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}

		header, payload, err := parseUDPRequest(buf[:n])
		if err != nil {
			log.Println("[SOCKS5] [UDP] parse error:", err)
			continue
		}
		if header.Frag != 0 {
			continue
		}

		targetUDPAddr, err := resolveUDPTarget(header)
		if err != nil {
			log.Println("[SOCKS5] [UDP] resolve error:", err)
			continue
		}

		key := srcAddr.String() + "|" + targetUDPAddr.String()
		var session *udpSession
		if v, ok := sessions.Load(key); ok {
			session = v.(*udpSession)
		} else {
			targetConn, err := net.DialUDP("udp", nil, targetUDPAddr)
			if err != nil {
				log.Println("[SOCKS5] [UDP] dial error:", err)
				continue
			}
			session = &udpSession{targetConn: targetConn, clientAddr: srcAddr}
			sessions.Store(key, session)
			go forwardUDPResponse(ctx, udpConn, session, targetUDPAddr)
		}

		if _, err := session.targetConn.Write(payload); err != nil {
			log.Println("[SOCKS5] [UDP] forward error:", err)
		}
	}
}

func forwardUDPResponse(ctx context.Context, udpConn *net.UDPConn, session *udpSession, targetAddr *net.UDPAddr) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := session.targetConn.SetReadDeadline(time.Now().Add(constant.IdleTimeout)); err != nil {
			return
		}
		n, _, err := session.targetConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		resp := buildUDPResponse(targetAddr, buf[:n])
		if _, err := udpConn.WriteToUDP(resp, session.clientAddr); err != nil {
			return
		}
	}
}

func parseUDPRequest(data []byte) (*UDPHeader, []byte, error) {
	buf := bytes.NewBuffer(data)
	header, err := parseUDPHeader(buf)
	if err != nil {
		return nil, nil, err
	}
	payload := buf.Bytes()
	return header, payload, nil
}

func resolveUDPTarget(header *UDPHeader) (*net.UDPAddr, error) {
	switch header.AddrType {
	case constant.AddrIPv4, constant.AddrIPv6:
		return &net.UDPAddr{IP: net.IP(header.DstAddr), Port: int(header.DstPort)}, nil
	case constant.AddrDomain:
		ip, err := net.ResolveIPAddr("ip", string(header.DstAddr))
		if err != nil {
			return nil, err
		}
		return &net.UDPAddr{IP: ip.IP, Port: int(header.DstPort)}, nil
	default:
		return nil, errors.New("unsupported address type")
	}
}

func buildUDPResponse(targetAddr *net.UDPAddr, payload []byte) []byte {
	resp := []byte{0x00, 0x00, 0x00}
	if ip4 := targetAddr.IP.To4(); ip4 != nil {
		resp = append(resp, constant.AddrIPv4)
		resp = append(resp, ip4...)
	} else {
		resp = append(resp, constant.AddrIPv6)
		resp = append(resp, targetAddr.IP.To16()...)
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetAddr.Port))
	resp = append(resp, portBuf...)
	resp = append(resp, payload...)
	return resp
}

func writeUDPAssociateResponse(conn net.Conn, addr net.Addr) error {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return errors.New("udp: invalid address type")
	}
	resp := []byte{constant.Socks5Version, 0x00, 0x00}
	if ip4 := udpAddr.IP.To4(); ip4 != nil {
		resp = append(resp, constant.AddrIPv4)
		resp = append(resp, ip4...)
	} else {
		resp = append(resp, constant.AddrIPv6)
		resp = append(resp, udpAddr.IP.To16()...)
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(udpAddr.Port))
	resp = append(resp, portBuf...)
	_, err := conn.Write(resp)
	return err
}
