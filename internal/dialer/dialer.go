package dialer

import (
	"errors"
	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/forward"
	socks5proto "gocks/internal/protocol/socks5"
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

// DialUdpAssociation opens a UDP association through the configured upstream
// proxy. It returns (nil, nil, nil) when no forward proxy is configured, in
// which case the caller should relay UDP directly.
func DialUdpAssociation() (net.Conn, *socks5proto.Addr, error) {
	if !config.ForwardRequired {
		return nil, nil, nil
	}
	switch config.ForwardConfig.Scheme {
	case constant.Socks5:
		return forward.DialSocks5UDPAssociate()
	default:
		return nil, nil, errors.New("udp over this forward scheme is not supported")
	}
}
