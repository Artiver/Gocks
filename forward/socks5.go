package forward

import (
	"Gocks/global"
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
	// todo: 判断地址类型
	req := global.ClientRequestDomain // SOCKS5, 连接命令, 保留字节, 使用域名
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

// socks5Handshake 实现 SOCKS5 的握手过程
func socks5Handshake(conn net.Conn) error {
	// 客户端发送版本和认证方法
	_, err := conn.Write([]byte{0x05, 0x01, 0x00}) // SOCKS5, 1个方法, 不需要认证
	if err != nil {
		return err
	}

	// 服务器响应选择的认证方法
	response := make([]byte, 2)
	_, err = io.ReadFull(conn, response)
	if err != nil {
		return err
	}

	// 确保服务器选择了不需要认证的方法
	// todo: 认证流程
	if response[0] != 0x05 || response[1] != 0x00 {
		return errors.New("不支持的认证方法")
	}

	return nil
}

func judgeAddrType(address string) int {
	ip := net.ParseIP(address)
	if ip != nil && ip.To4() != nil {
		return global.AddrIPv4
	}
	return global.AddrIPv6
}
