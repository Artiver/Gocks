package forward

import (
	"Gocks/global"
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/url"
)

func DialHTTPProxyConnection(address string) (net.Conn, error) {
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
		Header: global.ForwardConfig.HttpAuthHeader,
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
}
