package forward

import (
	"errors"
	"gocks/internal/config"
	"gocks/internal/constant"
	"io"
	"net"
	"strconv"
	"time"
)

func DialSocks5ProxyConnection(address string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", config.ForwardConfig.BindAddr, constant.TcpConnectTimeout)
	if err != nil {
		return nil, err
	}
	if err = socks5Handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		conn.Close()
		return nil, err
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		conn.Close()
		return nil, err
	}

	req := buildCommandRequest(constant.CmdConnect, host)
	req = append(req, byte(portNum>>8), byte(portNum&0xff))
	if _, err = conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	if err := readSocks5Response(conn); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func DialSocks5UDPAssociate(address string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", config.ForwardConfig.BindAddr, constant.TcpConnectTimeout)
	if err != nil {
		return nil, err
	}
	if err = socks5Handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		conn.Close()
		return nil, err
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		conn.Close()
		return nil, err
	}

	req := buildCommandRequest(constant.CmdUDP, host)
	req = append(req, byte(portNum>>8), byte(portNum&0xff))
	if _, err = conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	if err := readSocks5Response(conn); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func readSocks5Response(conn net.Conn) error {
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return err
	}
	if respHeader[0] != constant.Socks5Version {
		return errors.New("invalid SOCKS5 version in response")
	}
	if respHeader[1] != 0x00 {
		return errors.New("connection failed, rep code: " + strconv.Itoa(int(respHeader[1])))
	}

	var addrLen int
	switch respHeader[3] {
	case constant.AddrIPv4:
		addrLen = net.IPv4len
	case constant.AddrIPv6:
		addrLen = net.IPv6len
	case constant.AddrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		addrLen = int(lenBuf[0])
	default:
		return errors.New("unsupported address type in response")
	}

	rest := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return err
	}
	return nil
}

func socks5Handshake(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return err
	}
	defer conn.SetReadDeadline(time.Time{})

	_, err := conn.Write(constant.ClientInitialReq)
	if err != nil {
		return err
	}

	response := make([]byte, 2)
	_, err = io.ReadFull(conn, response)
	if err != nil {
		return err
	}

	if response[0] != constant.Socks5Version {
		return errors.New("invalid SOCKS5 version in handshake")
	}

	switch response[1] {
	case 0x00:
		return nil
	case 0x02:
		if config.ForwardConfig.Socks5Auth == nil {
			return errors.New("forward socks5 server requires authentication but none configured")
		}
		if _, err = conn.Write(config.ForwardConfig.Socks5Auth); err != nil {
			return errors.New("write auth credentials error")
		}
		if _, err = io.ReadFull(conn, response); err != nil {
			return errors.New("read auth result error")
		}
		if response[0] != 0x01 || response[1] != 0x00 {
			return errors.New("socks5 authentication failed")
		}
		return nil
	default:
		return errors.New("no acceptable authentication method")
	}
}

func buildCommandRequest(cmd byte, address string) []byte {
	var req []byte
	ip := net.ParseIP(address)
	if ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			req = []byte{constant.Socks5Version, cmd, 0x00, constant.AddrIPv4}
			req = append(req, ipv4...)
			return req
		}
		req = []byte{constant.Socks5Version, cmd, 0x00, constant.AddrIPv6}
		req = append(req, ip.To16()...)
		return req
	}
	req = []byte{constant.Socks5Version, cmd, 0x00, constant.AddrDomain}
	req = append(req, byte(len(address)))
	req = append(req, []byte(address)...)
	return req
}
