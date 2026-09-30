package socks5

import (
	"context"
	"errors"
	"fmt"
	"gocks/internal/config"
	"gocks/internal/constant"
	socks5proto "gocks/internal/protocol/socks5"
	"gocks/internal/server"
	"gocks/internal/tunnel"
	"log"
	"net"
	"time"
)

// Run serves SOCKS5 until ctx is cancelled.
func Run(ctx context.Context) error {
	return server.Serve(ctx, "SOCKS5 proxy", config.ProxyConfig.BindAddr, func(conn net.Conn) {
		HandleSocks5Connection(conn, nil)
	})
}

// HandleSocks5Connection serves one client. firstBuff carries the bytes the
// mixed-mode dispatcher pre-read to tell HTTP and SOCKS5 apart; they are
// replayed so the handshake sees the complete client greeting.
func HandleSocks5Connection(conn net.Conn, firstBuff []byte) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()

	if len(firstBuff) > 0 {
		conn = tunnel.NewPrefixConn(firstBuff, conn)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Println("connection close error", err)
		}
	}()

	clientID, err := socks5Handshake(conn)
	if err != nil {
		log.Println("Handshake error:", err)
		return
	}
	if clientID != "" {
		log.Printf("[SOCKS5] client %q from %s", clientID, conn.RemoteAddr())
	}

	if err := socks5HandleRequest(conn); err != nil {
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
	auth := config.ProxyConfig.Auth
	if auth == nil {
		return socks5proto.NewServerSelector()
	}
	return socks5proto.NewServerSelector(socks5proto.Credential{
		Username: auth.Username,
		Password: auth.Password,
	})
}

func socks5HandleRequest(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return err
	}

	// ReadRequest frames the request exactly, so any payload the client sent
	// right after it stays in the socket and is forwarded by the command
	// handler instead of being discarded.
	req, err := socks5proto.ReadRequest(conn)
	if err != nil {
		if errors.Is(err, socks5proto.ErrBadAddrType) {
			if werr := writeReply(conn, socks5proto.RepAddrUnsupported, nil); werr != nil {
				log.Println("write reply error:", werr)
			}
		}
		return err
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
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
		if werr := writeReply(conn, socks5proto.RepCmdUnsupported, nil); werr != nil {
			log.Println("write reply error:", werr)
		}
		return fmt.Errorf("unsupported command %d", req.Cmd)
	}
}

// writeReply sends one reply. A nil addr is encoded as 0.0.0.0:0, which is what
// RFC 1928 §6 allows when no bound address is meaningful.
func writeReply(conn net.Conn, rep byte, addr *socks5proto.Addr) error {
	return socks5proto.NewReply(rep, addr).Write(conn)
}

// writeBndReply sends a reply carrying the given bound address, falling back to
// no address (0.0.0.0:0) when it cannot be represented.
func writeBndReply(conn net.Conn, rep byte, bnd net.Addr) error {
	var addr *socks5proto.Addr
	if bnd != nil {
		if parsed, err := socks5proto.NewAddr(bnd.String()); err == nil {
			addr = parsed
		}
	}
	return writeReply(conn, rep, addr)
}
