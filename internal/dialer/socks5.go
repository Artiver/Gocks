package dialer

import (
	"errors"
	"fmt"
	"gocks/internal/config"
	"gocks/internal/constant"
	socks5proto "gocks/internal/protocol/socks5"
	"net"
	"time"
)

// credential converts the hop's configured auth to the protocol layer type.
func credential(auth *config.Auth) *socks5proto.Credential {
	if auth == nil {
		return nil
	}
	return &socks5proto.Credential{Username: auth.Username, Password: auth.Password}
}

// dialSocks5Hop performs the SOCKS5 client handshake with hop over the already
// established conn and asks it to connect to address.
func dialSocks5Hop(conn net.Conn, hop config.Url, address string) error {
	if err := conn.SetDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return err
	}
	if err := socks5proto.ClientHandshake(conn, credential(hop.Auth)); err != nil {
		return err
	}

	addr, err := socks5proto.NewAddr(address)
	if err != nil {
		return err
	}
	// ReadReply frames the reply by address type, so IPv6/domain bound
	// addresses do not leave trailing bytes on the tunnel stream.
	reply, err := exchange(conn, socks5proto.CmdConnect, addr)
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

// exchange writes one request and reads its reply over the hop connection.
func exchange(conn net.Conn, cmd byte, addr *socks5proto.Addr) (*socks5proto.Reply, error) {
	if err := socks5proto.NewRequest(cmd, addr).Write(conn); err != nil {
		return nil, err
	}
	return socks5proto.ReadReply(conn)
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

	if err := conn.SetDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		conn.Close()
		return nil, nil, err
	}
	if err := socks5proto.ClientHandshake(conn, credential(hop.Auth)); err != nil {
		conn.Close()
		return nil, nil, err
	}

	// 0.0.0.0:0 asks the upstream to choose the relay endpoint.
	reply, err := exchange(conn, socks5proto.CmdUDP, &socks5proto.Addr{
		Type: socks5proto.AddrIPv4,
		Host: "0.0.0.0",
	})
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
