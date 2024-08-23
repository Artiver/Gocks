package forward

import (
	"Gocks/global"
	"bytes"
	"errors"
	"io"
	"net"
)

func DialSocks5ProxyConnection(address string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", global.ForwardConfig.BindAddr, global.TcpConnectTimeout)

	if err = socks5Handshake(conn); err != nil {
		return nil, err
	}

	// 解析目标地址
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	// 将端口号转换为字节
	portNum, err := net.LookupPort("tcp", port)
	if err != nil {
		return nil, err
	}

	// 建立连接请求
	var req []byte
	hostType := judgeAddrType(host)
	switch hostType {
	case global.AddrIPv4:
		req = global.ClientRequestIPv4
	case global.AddrIPv6:
		req = global.ClientRequestIPv6
	case global.AddrDomain:
		req = global.ClientRequestDomain
	}
	req = append(req, byte(len(host)))
	req = append(req, host...)
	req = append(req, []byte{byte(portNum >> 8), byte(portNum & 0xff)}...)

	// 发送连接请求
	_, err = conn.Write(req)
	if err != nil {
		return nil, err
	}

	// 读取服务器的响应
	resp := make([]byte, 10) // 响应至少10个字节
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		return nil, err
	}

	// 检查响应是否成功
	if resp[1] != 0x00 {
		return nil, errors.New("连接失败，响应码")
	}

	return conn, nil
}

func socks5Handshake(conn net.Conn) error {
	_, err := conn.Write(global.ClientInitialReq)
	if err != nil {
		return err
	}

	response := make([]byte, 2)
	_, err = io.ReadFull(conn, response)
	if err != nil {
		return err
	}

	if bytes.Equal(response, global.ResponseAuthNone) {
		return nil
	} else if bytes.Equal(response, global.ResponseAuthUsernamePassword) {
		if global.ForwardConfig.Socks5Auth == nil {
			return errors.New("forward socks5 server need authentication")
		}
		req := []byte{0x01}
		req = append(req, byte(len(global.ForwardConfig.Socks5Auth.Username)))
		req = append(req, global.ForwardConfig.Socks5Auth.Username...)
		req = append(req, byte(len(global.ForwardConfig.Socks5Auth.Password)))
		req = append(req, global.ForwardConfig.Socks5Auth.Password...)
		_, err = conn.Write(req)
		if err != nil {
			return errors.New("response auth info error")
		}
		_, err = io.ReadFull(conn, response)
		if err != nil {
			return errors.New("receive auth result error")
		}
		if bytes.Equal(response, global.AuthSuccess) {
			return nil
		} else {
			return errors.New("socks5 auth error")
		}
	} else {
		return errors.New("unknown response")
	}
}

func judgeAddrType(address string) int {
	ip := net.ParseIP(address)
	if ip != nil {
		if ip.To4() != nil {
			return global.AddrIPv4
		}
		return global.AddrIPv6
	}
	return global.AddrDomain
}
