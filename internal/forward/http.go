package forward

import (
	"bufio"
	"errors"
	"gocks/internal/config"
	"gocks/internal/constant"
	"net"
	"net/http"
	"net/url"
	"time"
)

func DialHTTPProxyConnection(address string) (net.Conn, error) {
	tcpConn, err := net.DialTimeout("tcp", config.ForwardConfig.BindAddr, constant.ForwardDialTimeout)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(constant.HandshakeTimeout)
	if err := tcpConn.SetDeadline(deadline); err != nil {
		tcpConn.Close()
		return nil, err
	}

	req := &http.Request{
		Method: constant.ConnectMethod,
		URL:    &url.URL{Host: address},
		Host:   address,
		Header: config.ForwardConfig.HttpAuthHeader,
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

	if err := tcpConn.SetDeadline(time.Time{}); err != nil {
		tcpConn.Close()
		return nil, err
	}

	return tcpConn, nil
}
