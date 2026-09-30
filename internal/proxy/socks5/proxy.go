package socks5

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/tunnel"
	"io"
	"log"
	"net"
	"time"
)

func Run() {
	listen, err := net.Listen("tcp", config.ProxyConfig.BindAddr)
	if err != nil {
		log.Fatalln("Error listening:", err)
	}
	defer func(listen net.Listener) {
		err = listen.Close()
		if err != nil {
			log.Println("listening close error", err)
		}
	}(listen)

	log.Println("SOCKS5 proxy listening", config.ProxyConfig.BindAddr)

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go HandleSocks5Connection(&conn, nil)
	}
}

func HandleSocks5Connection(conn *net.Conn, firstBuff []byte) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Println("connection close error", err)
		}
	}(*conn)

	var c net.Conn = *conn
	if len(firstBuff) > 0 {
		c = tunnel.NewPrefixConn(firstBuff, *conn)
	}

	if err := socks5Handshake(&c); err != nil {
		log.Println("Handshake error:", err)
		return
	}

	if err := socks5HandleRequest(&c); err != nil {
		log.Println("Request handling error:", err)
	}
}

func socks5Handshake(conn *net.Conn) error {
	if err := (*conn).SetReadDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return err
	}

	header := make([]byte, 2)
	if _, err := io.ReadFull(*conn, header); err != nil {
		return errors.New("failed to read handshake header")
	}
	if header[0] != constant.Socks5Version {
		return errors.New("unsupported SOCKS version")
	}
	nmethods := int(header[1])
	if nmethods == 0 {
		return errors.New("no authentication methods offered")
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(*conn, methods); err != nil {
		return errors.New("failed to read authentication methods")
	}

	needAuth := config.ProxyConfig.Socks5Auth != nil
	if needAuth {
		if !bytes.Contains(methods, []byte{0x02}) {
			_, _ = (*conn).Write([]byte{constant.Socks5Version, 0xFF})
			return errors.New("client does not support username/password authentication")
		}
		if _, err := (*conn).Write(constant.ResponseAuthUsernamePassword); err != nil {
			return err
		}
		if err := socks5ReadAuth(conn); err != nil {
			return err
		}
	} else {
		if !bytes.Contains(methods, []byte{0x00}) {
			_, _ = (*conn).Write([]byte{constant.Socks5Version, 0xFF})
			return errors.New("client does not support no authentication")
		}
		if _, err := (*conn).Write(constant.ResponseAuthNone); err != nil {
			return err
		}
	}

	return nil
}

func socks5ReadAuth(conn *net.Conn) error {
	if err := (*conn).SetReadDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return err
	}

	authHeader := make([]byte, 2)
	if _, err := io.ReadFull(*conn, authHeader); err != nil {
		return errors.New("failed to read authentication request")
	}
	if authHeader[0] != 0x01 {
		return errors.New("unsupported authentication version")
	}

	usernameLen := int(authHeader[1])
	username := make([]byte, usernameLen)
	if _, err := io.ReadFull(*conn, username); err != nil {
		return errors.New("failed to read username")
	}

	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(*conn, passLenBuf); err != nil {
		return errors.New("failed to read password length")
	}
	passwordLen := int(passLenBuf[0])
	password := make([]byte, passwordLen)
	if _, err := io.ReadFull(*conn, password); err != nil {
		return errors.New("failed to read password")
	}

	expectedUser := []byte(config.ProxyConfig.Username)
	expectedPass := []byte(config.ProxyConfig.Password)
	if subtle.ConstantTimeCompare(username, expectedUser) != 1 ||
		subtle.ConstantTimeCompare(password, expectedPass) != 1 {
		_, _ = (*conn).Write(constant.AuthFailed)
		return errors.New("authentication failed")
	}

	if _, err := (*conn).Write(constant.AuthSuccess); err != nil {
		return err
	}
	return nil
}

func socks5HandleRequest(conn *net.Conn) error {
	if err := (*conn).SetReadDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(*conn, header); err != nil {
		return errors.New("failed to read request header")
	}
	if header[0] != constant.Socks5Version {
		return errors.New("unsupported SOCKS version")
	}

	targetAddr, err := readRequestAddr(*conn, header[3])
	if err != nil {
		return err
	}

	if err := (*conn).SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	cmd := header[1]
	switch cmd {
	case constant.CmdConnect:
		return handleConnect(conn, targetAddr)
	case constant.CmdBind:
		return handleBind(conn, targetAddr)
	case constant.CmdUDP:
		return handleUDPAssociate(conn)
	default:
		return errors.New("unsupported command")
	}
}

func readRequestAddr(r io.Reader, addrType byte) (string, error) {
	var addr string
	var port uint16

	portBuf := make([]byte, 2)

	switch addrType {
	case constant.AddrIPv4:
		ipBuf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, ipBuf); err != nil {
			return "", errors.New("failed to read IPv4 address")
		}
		addr = net.IP(ipBuf).String()
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return "", errors.New("failed to read port")
		}
		port = binary.BigEndian.Uint16(portBuf)
	case constant.AddrIPv6:
		ipBuf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, ipBuf); err != nil {
			return "", errors.New("failed to read IPv6 address")
		}
		addr = net.IP(ipBuf).String()
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return "", errors.New("failed to read port")
		}
		port = binary.BigEndian.Uint16(portBuf)
	case constant.AddrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", errors.New("failed to read domain length")
		}
		addrLen := int(lenBuf[0])
		if addrLen == 0 {
			return "", errors.New("empty domain address")
		}
		domainBuf := make([]byte, addrLen)
		if _, err := io.ReadFull(r, domainBuf); err != nil {
			return "", errors.New("failed to read domain")
		}
		addr = string(domainBuf)
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return "", errors.New("failed to read port")
		}
		port = binary.BigEndian.Uint16(portBuf)
	default:
		return "", errors.New("unsupported address type")
	}
	return tunnel.FormatAddress(addr, port), nil
}
