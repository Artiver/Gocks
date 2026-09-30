package socks5

import (
	"encoding/binary"
	"errors"
	"gocks/internal/config"
	"gocks/internal/constant"
	socks5proto "gocks/internal/protocol/socks5"
	"gocks/internal/tunnel"
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

	var c net.Conn = *conn
	if len(firstBuff) > 0 {
		// Replay the bytes pre-read by the mixed-mode dispatcher so the
		// handshake sees the complete client greeting.
		c = tunnel.NewPrefixConn(firstBuff, *conn)
	}
	defer func() {
		if err := c.Close(); err != nil {
			log.Println("connection close error", err)
		}
	}()

	clientID, err := socks5Handshake(c)
	if err != nil {
		log.Println("Handshake error:", err)
		return
	}
	if clientID != "" {
		log.Printf("[SOCKS5] client %q from %s", clientID, c.RemoteAddr())
	}

	if err := socks5HandleRequest(&c); err != nil {
		log.Println("Request handling error:", err)
	}
}

func socks5Handshake(conn net.Conn) (string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return "", err
	}
	return socks5proto.ServerHandshake(conn, newSelector())
}

// newSelector builds the authentication selector from the proxy configuration.
// Authentication is mandatory when credentials were configured via -L.
func newSelector() socks5proto.Selector {
	if config.ProxyConfig.Socks5Auth == nil {
		return socks5proto.NewServerSelector()
	}
	return socks5proto.NewServerSelector(socks5proto.Credential{
		Username: config.ProxyConfig.Username,
		Password: config.ProxyConfig.Password,
	})
}

func socks5HandleRequest(conn *net.Conn) error {
	buf := make([]byte, constant.Socks5HandleBytes)

	if err := (*conn).SetReadDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return err
	}
	n, err := (*conn).Read(buf)
	if err != nil || n < 7 {
		return errors.New("failed to read request")
	}
	if err := (*conn).SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	if buf[0] != constant.Socks5Version {
		return errors.New("unsupported SOCKS version")
	}

	targetAddr, err := handleRequestAddr(buf, n)
	if err != nil {
		return err
	}

	cmd := buf[1]
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

func handleRequestAddr(buf []byte, n int) (string, error) {
	addrType := buf[3]
	var addr string
	var port uint16

	switch addrType {
	case constant.AddrIPv4:
		if n < 10 {
			return "", errors.New("invalid IPv4 address")
		}
		addr = net.IP(buf[4:8]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case constant.AddrIPv6:
		if n < 22 {
			return "", errors.New("invalid IPv6 address")
		}
		addr = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])
	case constant.AddrDomain:
		addrLen := int(buf[4])
		if 5+addrLen+2 > n {
			return "", errors.New("invalid domain address")
		}
		addr = string(buf[5 : 5+addrLen])
		port = binary.BigEndian.Uint16(buf[5+addrLen : 7+addrLen])
	default:
		return "", errors.New("unsupported address type")
	}
	return tunnel.FormatAddress(addr, port), nil
}
