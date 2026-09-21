package forward

import (
	"Gocks/global"
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

// DialHTTPProxyConnection 通过上游 HTTP 代理建立 CONNECT 隧道。
func DialHTTPProxyConnection(address string) (net.Conn, error) {
	// 拨号到上游代理服务器（带超时）
	tcpConn, err := net.DialTimeout("tcp", global.ForwardConfig.BindAddr, global.ForwardDialTimeout)
	if err != nil {
		return nil, err
	}

	// 设置请求写入和响应读取的超时
	deadline := time.Now().Add(global.HandshakeTimeout)
	if err := tcpConn.SetDeadline(deadline); err != nil {
		tcpConn.Close()
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

	// 重置 deadline，后续数据由 TransportData 的 idle timeout 管理
	if err := tcpConn.SetDeadline(time.Time{}); err != nil {
		tcpConn.Close()
		return nil, err
	}

	return tcpConn, nil
}
