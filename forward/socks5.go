package forward

import (
	"Gocks/global"
	"golang.org/x/net/proxy"
	"net"
)

func DialSocks5ProxyConnection(address string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", global.ForwardConfig.BindAddr, global.ForwardConfig.Socks5Auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", address)
}
