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

// socks5ClientHandshake negotiates the authentication method with the upstream
// SOCKS5 server, offering username/password in addition to no-auth when
// credentials are configured.
func socks5ClientHandshake(conn net.Conn) error {
	methods := []byte{socks5proto.MethodNoAuth}
	if config.ForwardConfig.Username != "" || config.ForwardConfig.Password != "" {
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
		if config.ForwardConfig.Username == "" && config.ForwardConfig.Password == "" {
			return errors.New("socks5: upstream requires authentication but none is configured")
		}
		req := socks5proto.NewUserPassRequest(
			socks5proto.UserPassVersion,
			config.ForwardConfig.Username,
			config.ForwardConfig.Password,
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

// DialSocks5ProxyConnection connects to address through the configured upstream
// SOCKS5 proxy.
func DialSocks5ProxyConnection(address string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", config.ForwardConfig.BindAddr, constant.TcpConnectTimeout)
	if err != nil {
		return nil, err
	}

	if err := socks5ClientHandshake(conn); err != nil {
		conn.Close()
		return nil, err
	}

	addr, err := socks5proto.NewAddr(address)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if err := conn.SetDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		conn.Close()
		return nil, err
	}
	if err := socks5proto.NewRequest(socks5proto.CmdConnect, addr).Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	// ReadReply frames the reply by address type, so IPv6/domain bound
	// addresses do not leave trailing bytes on the tunnel stream.
	reply, err := socks5proto.ReadReply(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}

	if reply.Rep != socks5proto.RepSucceeded {
		conn.Close()
		return nil, fmt.Errorf("socks5: upstream connect failed: %s", socks5proto.ReprString(reply.Rep))
	}
	return conn, nil
}

// DialSocks5UDPAssociate establishes a UDP association with the upstream
// SOCKS5 server. It returns the TCP control connection that keeps the
// association alive and the relay address datagrams must be sent to.
func DialSocks5UDPAssociate() (net.Conn, *socks5proto.Addr, error) {
	conn, err := net.DialTimeout("tcp", config.ForwardConfig.BindAddr, constant.TcpConnectTimeout)
	if err != nil {
		return nil, nil, err
	}

	if err := socks5ClientHandshake(conn); err != nil {
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
