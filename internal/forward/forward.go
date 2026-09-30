package forward

import (
	"errors"
	"fmt"
	"gocks/internal/config"
	"gocks/internal/constant"
	"net"
)

// DialThroughChain connects to address through the ordered chain of upstream
// proxies, nearest hop first. The first hop is dialled directly; every
// following hop is reached over the tunnel the previous hops built, so each
// hop runs the same handshake as the classic single-upstream case.
//
// chain must not be empty.
func DialThroughChain(chain []config.Url, address string) (net.Conn, error) {
	if len(chain) == 0 {
		return nil, errors.New("forward: empty proxy chain")
	}

	conn, err := net.DialTimeout("tcp", chain[0].BindAddr, constant.TcpConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("forward: hop[0] %s: %w", chain[0].BindAddr, err)
	}

	for i, hop := range chain {
		target := address
		if i < len(chain)-1 {
			// Every hop but the last is asked to reach the next proxy.
			target = chain[i+1].BindAddr
		}
		if err := dialHop(conn, hop, target); err != nil {
			conn.Close()
			return nil, fmt.Errorf("forward: hop[%d] %s: %w", i, hop.BindAddr, err)
		}
	}
	return conn, nil
}

// dialHop performs one hop's handshake over conn, asking the proxy to connect
// to address.
func dialHop(conn net.Conn, hop config.Url, address string) error {
	switch hop.Scheme {
	case constant.Socks5:
		return dialSocks5Hop(conn, hop, address)
	case constant.HTTP:
		return dialHTTPHop(conn, hop, address)
	default:
		return fmt.Errorf("forward: unsupported scheme %q", hop.Scheme)
	}
}
