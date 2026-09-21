package http

import (
	"Gocks/global"
	"Gocks/utils"
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func Run() {
	listen, err := net.Listen("tcp", global.ProxyConfig.BindAddr)
	if err != nil {
		log.Fatalln("Error listening:", err)
	}
	defer func(listen net.Listener) {
		err = listen.Close()
		if err != nil {
			log.Println("listening close error", err)
		}
	}(listen)

	log.Println("HTTP proxy listening", global.ProxyConfig.BindAddr)

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}

		go HandleHTTPConnection(&conn, nil)
	}
}

// HandleHTTPConnection 处理一个 HTTP 代理连接，支持 Keep-Alive 连接复用。
// firstBuff 非 nil 时表示 mix 模式已预读了首包数据。
func HandleHTTPConnection(conn *net.Conn, firstBuff []byte) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	if conn == nil {
		return
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Println("connection close error", err)
		}
	}(*conn)

	// 构建读取源：mix 模式传入预读数据时，先读前缀再读连接
	var reader io.Reader = *conn
	if firstBuff != nil {
		reader = utils.NewPrefixConn(firstBuff, *conn)
	}
	br := bufio.NewReader(reader)

	// Keep-Alive 循环：在同一条 TCP 连接上依次处理多个 HTTP 请求
	for {
		close, err := handleOneRequest(br, *conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				log.Println("[HTTP]", err)
			}
			return
		}
		if close {
			return
		}
	}
}

// handleOneRequest 解析并处理单个 HTTP 请求，返回是否应关闭连接。
func handleOneRequest(br *bufio.Reader, conn net.Conn) (bool, error) {
	// 设置请求读取超时
	if err := conn.SetReadDeadline(time.Now().Add(global.HandshakeTimeout)); err != nil {
		return true, err
	}

	req, err := http.ReadRequest(br)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
			return true, nil
		}
		return true, err
	}
	defer req.Body.Close()

	// 重置读取超时
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return true, err
	}

	// 认证检查
	if global.ProxyConfig.Socks5Auth != nil {
		if !checkProxyAuthorizationFromHeader(req.Header) {
			_, err := conn.Write(global.AuthRequiredResponse)
			if err != nil {
				log.Println("send 407 error:", err)
			}
			return true, nil
		}
	}

	// 路由分发：CONNECT 走隧道，其他方法走正向代理
	if req.Method == global.ConnectMethod {
		return handleConnectMethod(conn, br, req)
	}
	return handleProxyMethod(conn, req)
}

// handleConnectMethod 处理 CONNECT 隧道请求（HTTPS 代理）。
func handleConnectMethod(conn net.Conn, br *bufio.Reader, req *http.Request) (bool, error) {
	addr := req.Host
	if addr == "" && req.URL != nil {
		addr = req.URL.Host
	}
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	// 拨号到目标服务器
	server, err := utils.DialTcpConnection(addr)
	if err != nil {
		log.Println(err)
		conn.Write(global.BadGatewayResponse)
		return true, err
	}
	defer server.Close()

	clientAddr := conn.RemoteAddr().String()
	log.Printf("[HTTP] %s <--> %s", clientAddr, addr)

	// 写 200 Connection established
	if _, err = conn.Write(global.ConnectedResponse); err != nil {
		return true, err
	}

	// br 可能已缓冲 CONNECT 请求之后的客户端数据，需一并透传给目标
	var wrappedConn net.Conn = utils.NewReaderConn(br, conn)
	err = utils.TransportData(&server, &wrappedConn)
	if err != nil {
		log.Println("[HTTP]", err)
	}
	return true, nil
}

// handleProxyMethod 处理普通 HTTP 正向代理请求（GET/POST 等）。
func handleProxyMethod(conn net.Conn, req *http.Request) (bool, error) {
	// 解析目标地址
	addr := req.Host
	if addr == "" && req.URL != nil {
		addr = req.URL.Host
	}
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}

	// 拨号到目标服务器
	server, err := utils.DialTcpConnection(addr)
	if err != nil {
		log.Println(err)
		conn.Write(global.BadGatewayResponse)
		return true, err
	}
	defer server.Close()

	clientAddr := conn.RemoteAddr().String()
	log.Printf("[HTTP] %s <--> %s", clientAddr, addr)

	// 规范化请求头：删除代理特定头（hop-by-hop），避免泄露给目标
	req.Header.Del(global.BasicAuthHeader)
	req.Header.Del(global.ProxyConnectKey)
	// 添加 Via 头
	req.Header.Add(global.ViaHeader, global.ViaValue)

	// 对于绝对 URL 请求（代理形式 GET http://host/path），改为 origin-form 发送
	if req.URL.IsAbs() {
		req.URL.Scheme = ""
		req.URL.Host = ""
		req.RequestURI = req.URL.RequestURI()
	}

	// 写请求到目标服务器
	if err := req.Write(server); err != nil {
		return true, err
	}

	// 读取目标服务器响应
	serverBr := bufio.NewReader(server)
	resp, err := http.ReadResponse(serverBr, req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()

	// 添加 Via 头到响应
	resp.Header.Add(global.ViaHeader, global.ViaValue)

	// 判断是否 Keep-Alive
	close := shouldCloseConnection(req, resp)

	// 写响应到客户端
	if err := resp.Write(conn); err != nil {
		return true, err
	}

	return close, nil
}

// shouldCloseConnection 根据请求和响应判断是否应关闭连接。
func shouldCloseConnection(req *http.Request, resp *http.Response) bool {
	// HTTP/1.0 默认关闭，除非显式 Connection: keep-alive
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		return !strings.EqualFold(req.Header.Get("Connection"), "keep-alive")
	}
	// HTTP/1.1 默认 keep-alive，除非显式 Connection: close
	if strings.EqualFold(req.Header.Get("Connection"), "close") {
		return true
	}
	if resp.Close {
		return true
	}
	return false
}
