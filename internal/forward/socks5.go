package forward

import (
	"errors"
	"fmt"
	"gocks/internal/config"
	"gocks/internal/constant"
	socks5proto "gocks/internal/protocol/socks5"
	"io"
	"net"
	"time"
)

// socks5ClientHandshake negotiates the authentication method with a SOCKS5
// proxy over conn, offering username/password in addition to no-auth when the
// hop carries credentials.
func socks5ClientHandshake(conn net.Conn, hop config.Url) error {
	methods := []byte{socks5proto.MethodNoAuth}
	if hop.Auth != nil {
		methods = append(methods, socks5proto.MethodUserPass)
	}

	if err := conn.SetDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{}) //nolint:errcheck

	greeting := make([]byte, 0, 2+len(methods))
	greeting = append(greeting, socks5proto.Version, byte(len(methods)))
	greeting = append(greeting, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return err
	}

	var selected [2]byte
	if _, err := io.ReadFull(conn, selected[:]); err != nil {
		return err
	}
	if selected[0] != socks5proto.Version {
		return socks5proto.ErrBadVersion
	}

	switch selected[1] {
	case socks5proto.MethodNoAuth:
		return nil

	case socks5proto.MethodUserPass:
		if hop.Auth == nil {
			return errors.New("socks5: upstream requires authentication but none is configured")
		}
		req := socks5proto.NewUserPassRequest(
			socks5proto.UserPassVersion,
			hop.Auth.Username,
			hop.Auth.Password,
		)
		if err := req.Write(conn); err != nil {
			return err
		}
		resp, err := socks5proto.ReadUserPassResponse(conn)
		if err != nil {
			return err
		}
		if resp.Status != socks5proto.UserPassSuccess {
			return socks5proto.ErrAuthFailure
		}
		return nil

	case socks5proto.MethodNoAcceptable:
		return socks5proto.ErrBadMethod

	default:
		return fmt.Errorf("socks5: upstream selected unsupported method %d", selected[1])
	}
}

// dialSocks5Hop performs the SOCKS5 client handshake with hop over the already
// established conn and asks it to connect to address.
func dialSocks5Hop(conn net.Conn, hop config.Url, address string) error {
	if err := socks5ClientHandshake(conn, hop); err != nil {
		return err
	}

	addr, err := socks5proto.NewAddr(address)
	if err != nil {
		return err
	}

	if err := conn.SetDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return err
	}
	if err := socks5proto.NewRequest(socks5proto.CmdConnect, addr).Write(conn); err != nil {
		return err
	}
	// ReadReply frames the reply by address type, so IPv6/domain bound
	// addresses do not leave trailing bytes on the tunnel stream.
	reply, err := socks5proto.ReadReply(conn)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}

	if reply.Rep != socks5proto.RepSucceeded {
		return fmt.Errorf("socks5: upstream connect failed: %s", socks5proto.ReprString(reply.Rep))
	}
	return nil
}

// DialSocks5UDPAssociate establishes a UDP association with the SOCKS5 proxy
// hop. It returns the TCP control connection that keeps the association alive
// and the relay address datagrams must be sent to.
//
// An association is inherently single-hop: the relay address is only
// meaningful to a client sitting where hop is reachable, so the caller refuses
// a multi-hop chain before getting here.
func DialSocks5UDPAssociate(hop config.Url) (net.Conn, *socks5proto.Addr, error) {
	conn, err := net.DialTimeout("tcp", hop.BindAddr, constant.TcpConnectTimeout)
	if err != nil {
		return nil, nil, err
	}

	if err := socks5ClientHandshake(conn, hop); err != nil {
		conn.Close()
		return nil, nil, err
	}

	if err := conn.SetDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		conn.Close()
		return nil, nil, err
	}
	// 0.0.0.0:0 asks the upstream to choose the relay endpoint.
	req := socks5proto.NewRequest(socks5proto.CmdUDP, &socks5proto.Addr{
		Type: socks5proto.AddrIPv4,
		Host: "0.0.0.0",
	})
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, nil, err
	}
	reply, err := socks5proto.ReadReply(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, nil, err
	}

	if reply.Rep != socks5proto.RepSucceeded {
		conn.Close()
		return nil, nil, fmt.Errorf("socks5: upstream UDP associate failed: %s", socks5proto.ReprString(reply.Rep))
	}
	if reply.Addr == nil {
		conn.Close()
		return nil, nil, errors.New("socks5: upstream UDP associate returned no relay address")
	}
	return conn, reply.Addr, nil
}
