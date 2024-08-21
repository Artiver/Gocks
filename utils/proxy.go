package utils

import (
	"bufio"
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const ConnectMethod = "CONNECT"
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
		switch ForwardConfig.Scheme {
		case Socks5:
			dialer, err := proxy.SOCKS5("tcp", ForwardConfig.BindAddr, ForwardConfig.Socks5Auth, proxy.Direct)
			if err != nil {
				return nil, err
			}
			return dialer.Dial("tcp", address)
		case HTTP:
			tcpAddr, err := net.ResolveTCPAddr("tcp", ForwardConfig.BindAddr)
			if err != nil {
				return nil, err
			}
			tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
			if err != nil {
				return nil, err
			}
			req := &http.Request{
				Method: ConnectMethod,
				URL:    &url.URL{Host: address},
				Host:   address,
				Header: ForwardConfig.HttpBasicAuth,
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
		return net.DialTimeout("tcp", address, TcpConnectTimeout)
	}
}
