package dialer

import (
	"errors"
	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/forward"
	socks5proto "gocks/internal/protocol/socks5"
	"net"
)

// DialTcpConnection connects to address directly, or through the configured
// chain of upstream proxies when one is set.
func DialTcpConnection(address string) (net.Conn, error) {
	if len(config.ForwardChain) == 0 {
		return net.DialTimeout("tcp", address, constant.TcpConnectTimeout)
	}
	return forward.DialThroughChain(config.ForwardChain, address)
}

// DialUdpAssociation opens a UDP association through the configured upstream
// proxy. It returns (nil, nil, nil) when no forward proxy is configured, in
// which case the caller should relay UDP directly.
//
// Only a single SOCKS5 hop can carry UDP: the relay address a proxy returns is
// meaningful to a client that can reach that proxy, which a chain cannot
// provide, so a longer chain is refused instead of misrouted.
func DialUdpAssociation() (net.Conn, *socks5proto.Addr, error) {
	switch len(config.ForwardChain) {
	case 0:
		return nil, nil, nil

	case 1:
		hop := config.ForwardChain[0]
		if hop.Scheme != constant.Socks5 {
			return nil, nil, errors.New("udp over this forward scheme is not supported")
		}
		return forward.DialSocks5UDPAssociate(hop)

	default:
		return nil, nil, errors.New("udp associate through a forward chain of more than one hop is not supported")
	}
}
