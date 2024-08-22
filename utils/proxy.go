package utils

import (
	"Gocks/forward"
	"Gocks/global"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

func FormatAddress(ip string, port uint16) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	} else {
		return fmt.Sprintf("%s:%d", ip, port)
	}
}

func TransportData(source, target *net.Conn) error {
	errChan := make(chan error, 1)

	go func() {
		_, err := io.Copy(*source, *target)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(*target, *source)
		errChan <- err
	}()

	err := <-errChan
	if err != nil && err == io.EOF {
		err = nil
	}
	return err
}

func DialTcpConnection(address string) (net.Conn, error) {
	if global.ForwardRequired {
		switch global.ForwardConfig.Scheme {
		case global.Socks5:
			return forward.DialSocks5ProxyConnection(address)
		case global.HTTP:
			return forward.DialHTTPProxyConnection(address)
		default:
			return nil, errors.New("forward not supported yet")
		}
	} else {
		return net.DialTimeout("tcp", address, global.TcpConnectTimeout)
	}
}
