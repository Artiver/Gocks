package socks5

import (
	"context"
	"errors"
	"fmt"
	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/dialer"
	socks5proto "gocks/internal/protocol/socks5"
	"gocks/internal/server"
	"gocks/internal/tunnel"
	"log"
	"net"
	"time"
)

// Proxy serves SOCKS5 connections.
type Proxy struct {
	dialer  *dialer.Dialer
	auth    *config.Auth
	timeout time.Duration
}

// New returns a SOCKS5 proxy configured by cfg.
func New(cfg config.Config) *Proxy {
	return &Proxy{
		dialer:  dialer.New(cfg.Upstream),
		auth:    cfg.Listen.Auth,
		timeout: cfg.Timeout,
	}
}

// Run serves SOCKS5 until ctx is cancelled.
func Run(ctx context.Context, cfg config.Config) error {
	p := New(cfg)
	return server.Serve(ctx, "SOCKS5 proxy", cfg.Listen.Addr, func(conn net.Conn) {
		p.HandleConnection(conn, nil)
	})
}

// HandleConnection serves one client. firstBuff carries the bytes the
// mixed-mode dispatcher pre-read to tell HTTP and SOCKS5 apart; they are
// replayed so the handshake sees the complete client greeting.
func (p *Proxy) HandleConnection(conn net.Conn, firstBuff []byte) {
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

	clientID, err := p.handshake(conn)
	if err != nil {
		log.Println("Handshake error:", err)
		return
	}
	if clientID != "" {
		log.Printf("[SOCKS5] client %q from %s", clientID, conn.RemoteAddr())
	}

	if err := p.handleRequest(conn); err != nil {
		log.Println("Request handling error:", err)
	}
}

func (p *Proxy) handshake(conn net.Conn) (string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return "", err
	}
	return socks5proto.ServerHandshake(conn, p.selector())
}

// selector builds the authentication selector from the proxy configuration.
// Authentication is mandatory when credentials were configured via -L.
func (p *Proxy) selector() socks5proto.Selector {
	if p.auth == nil {
		return socks5proto.NewServerSelector()
	}
	return socks5proto.NewServerSelector(socks5proto.Credential{
		Username: p.auth.Username,
		Password: p.auth.Password,
	})
}

func (p *Proxy) handleRequest(conn net.Conn) error {
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
		return p.handleConnect(conn, req.Addr)
	case socks5proto.CmdBind:
		return p.handleBind(conn, req.Addr)
	case socks5proto.CmdUDP:
		return p.handleUDPAssociate(conn)
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

// failReply reports a generic failure to the client and returns err, unless the
// reply itself could not be delivered.
func failReply(conn net.Conn, err error) error {
	if werr := writeReply(conn, socks5proto.RepFailure, nil); werr != nil {
		return werr
	}
	return err
}
