package forward

import (
	"bytes"
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

	hostType := formatAddressRequest(host)
	hostType = append(hostType, []byte{byte(portNum >> 8), byte(portNum & 0xff)}...)

	_, err = conn.Write(hostType)
	if err != nil {
		conn.Close()
		return nil, err
	}

	resp := make([]byte, 10)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if resp[1] != 0x00 {
		conn.Close()
		return nil, errors.New("连接失败，响应码")
	}

	return conn, nil
}

func socks5Handshake(conn net.Conn) error {
	conn.SetReadDeadline(time.Now().Add(constant.HandshakeTimeout))
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

	if bytes.Equal(response, constant.ResponseAuthNone) {
		return nil
	} else if bytes.Equal(response, constant.ResponseAuthUsernamePassword) {
		if config.ForwardConfig.Socks5Auth == nil {
			return errors.New("forward socks5 server need authentication")
		}
		_, err = conn.Write(config.ForwardConfig.Socks5Auth)
		if err != nil {
			return errors.New("response auth info error")
		}
		_, err = io.ReadFull(conn, response)
		if err != nil {
			return errors.New("receive auth result error")
		}
		if bytes.Equal(response, constant.AuthSuccess) {
			return nil
		} else {
			return errors.New("socks5 auth error")
		}
	} else {
		return errors.New("unknown response")
	}
}

func formatAddressRequest(address string) []byte {
	var req []byte
	ip := net.ParseIP(address)
	if ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			req = constant.ClientRequestIPv4
			req = append(req, ipv4...)
			return req
		}
		req = constant.ClientRequestIPv6
		req = append(req, ip.To16()...)
		return req
	}
	req = constant.ClientRequestDomain
	req = append(req, byte(len(address)))
	req = append(req, []byte(address)...)
	return req
}
