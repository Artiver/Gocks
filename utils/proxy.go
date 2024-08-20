package utils

import (
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"strings"
	"time"
)

const Socks5HandleBytes = 256
const DefaultReadBytes = 512
const TcpConnectTimeout = 5 * time.Second

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
	if ForwardRequired {
		dialer, err := proxy.SOCKS5("tcp", Forward.BindAddr, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		return dialer.Dial("tcp", address)
	} else {
		return net.DialTimeout("tcp", address, TcpConnectTimeout)
	}
}
