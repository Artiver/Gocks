package socks5

import (
	"errors"
	"fmt"
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
	if err := (*conn).SetReadDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return err
	}

	// ReadRequest frames the request exactly, so any payload the client sent
	// right after it stays in the socket and is forwarded by the command
	// handler instead of being discarded.
	req, err := socks5proto.ReadRequest(*conn)
	if err != nil {
		if errors.Is(err, socks5proto.ErrBadAddrType) {
			if werr := writeReply(conn, socks5proto.RepAddrUnsupported); werr != nil {
				log.Println("write reply error:", werr)
			}
		}
		return err
	}

	if err := (*conn).SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	switch req.Cmd {
	case socks5proto.CmdConnect:
		return handleConnect(conn, req.Addr)
	case socks5proto.CmdBind:
		return handleBind(conn, req.Addr)
	case socks5proto.CmdUDP:
		return handleUDPAssociate(conn)
	default:
		if werr := writeReply(conn, socks5proto.RepCmdUnsupported); werr != nil {
			log.Println("write reply error:", werr)
		}
		return fmt.Errorf("unsupported command %d", req.Cmd)
	}
}

// writeReply sends a reply carrying no bound address.
func writeReply(conn *net.Conn, rep byte) error {
	return socks5proto.NewReply(rep, nil).Write(*conn)
}
