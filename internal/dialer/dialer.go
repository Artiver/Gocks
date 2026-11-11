package dialer

import (
	"errors"
	"gocks/internal/config"
	"gocks/internal/constant"
	socks5proto "gocks/internal/protocol/socks5"
	"net"
)

// Dialer establishes target connections directly or through the configured
// chain of upstream proxies.
type Dialer struct {
	upstream []config.Endpoint
}

// New returns a Dialer using the given upstream hop list in dial order.
func New(upstream []config.Endpoint) *Dialer {
	return &Dialer{upstream: upstream}
}

// DialTCP connects to address directly, or through the configured chain of
// upstream proxies when one is set.
func (d *Dialer) DialTCP(address string) (net.Conn, error) {
	if len(d.upstream) == 0 {
		return net.DialTimeout("tcp", address, constant.TcpConnectTimeout)
	}
	return DialThroughChain(d.upstream, address)
}

// DialUDPAssociation opens a UDP association through the configured upstream
// proxy. It returns (nil, nil, nil) when no upstream is configured, in which
// case the caller should relay UDP directly.
//
// Only a single SOCKS5 hop can carry UDP: the relay address a proxy returns is
// meaningful to a client that can reach that proxy, which a chain cannot
// provide, so a longer chain is refused instead of misrouted.
func (d *Dialer) DialUDPAssociation() (net.Conn, *socks5proto.Addr, error) {
	switch len(d.upstream) {
	case 0:
		return nil, nil, nil

	case 1:
		hop := d.upstream[0]
		if hop.Scheme != constant.Socks5 {
			return nil, nil, errors.New("udp over this upstream scheme is not supported")
		}
		return DialSocks5UDPAssociate(hop)

	default:
		return nil, nil, errors.New("udp associate through an upstream chain of more than one hop is not supported")
	}
}
