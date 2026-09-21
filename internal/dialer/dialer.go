package dialer

import (
	"errors"
	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/forward"
	"net"
)

func DialTcpConnection(address string) (net.Conn, error) {
	if config.ForwardRequired {
		switch config.ForwardConfig.Scheme {
		case constant.Socks5:
			return forward.DialSocks5ProxyConnection(address)
		case constant.HTTP:
			return forward.DialHTTPProxyConnection(address)
		default:
			return nil, errors.New("forward not supported yet")
		}
	} else {
		return net.DialTimeout("tcp", address, constant.TcpConnectTimeout)
	}
}
