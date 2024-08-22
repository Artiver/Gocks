package utils

import (
	"Gocks/global"
	"bufio"
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/url"
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
			dialer, err := proxy.SOCKS5("tcp", global.ForwardConfig.BindAddr, global.ForwardConfig.Socks5Auth, proxy.Direct)
			if err != nil {
				return nil, err
			}
			return dialer.Dial("tcp", address)
		case global.HTTP:
			tcpAddr, err := net.ResolveTCPAddr("tcp", global.ForwardConfig.BindAddr)
			if err != nil {
				return nil, err
			}
			tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
			if err != nil {
				return nil, err
			}
			req := &http.Request{
				Method: global.ConnectMethod,
				URL:    &url.URL{Host: address},
				Host:   address,
				Header: global.ForwardConfig.HttpBasicAuth,
			}
			if err = req.Write(tcpConn); err != nil {
				tcpConn.Close()
				return nil, err
			}
			resp, err := http.ReadResponse(bufio.NewReader(tcpConn), req)
			if err != nil {
				tcpConn.Close()
				return nil, err
			}
			if resp.StatusCode != http.StatusOK {
				tcpConn.Close()
				return nil, errors.New(resp.Status)
			}
			return tcpConn, nil
		default:
			return nil, errors.New("forward not supported yet")
		}
	} else {
		return net.DialTimeout("tcp", address, global.TcpConnectTimeout)
	}
}
