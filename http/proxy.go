package http

import (
	"Gocks/global"
	"Gocks/utils"
	"bytes"
	"fmt"
	"log"
	"net"
	"net/url"
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

	if firstBuff == nil {
		firstBuff = make([]byte, global.DefaultReadBytes)
		if err := (*conn).SetReadDeadline(time.Now().Add(global.HandshakeTimeout)); err != nil {
			log.Println("set read deadline error")
			return
		}
		n, err := (*conn).Read(firstBuff)
		if err != nil || n < 1 {
			log.Println("read http data error")
			return
		}
		if err := (*conn).SetReadDeadline(time.Time{}); err != nil {
			log.Println("reset read deadline error")
			return
		}
		firstBuff = firstBuff[:n]
	}

	index := bytes.IndexByte(firstBuff, global.CR)
	if index == -1 {
		log.Println("not http proxy request")
		return
	}
	firstLine := string(firstBuff[:index])

	if global.ProxyConfig.Socks5Auth != nil {
		if index+2 > len(firstBuff) {
			log.Println("malformed http request")
			return
		}
		headers := parseHeaders(firstBuff[index+2:])
		if !checkProxyAuthorization(headers) {
			_, err := (*conn).Write(global.AuthRequiredResponse)
			if err != nil {
				log.Println("send 407 error:", err)
			}
			return
		}
	}

	var method, rawUrl string
	_, err := fmt.Sscanf(firstLine, "%s %s", &method, &rawUrl)
	if err != nil {
		log.Println("parse http request header error", firstLine)
		return
	}

	// CONNECT www.google.com:443 HTTP/1.1
	justHttpsProxy := method == global.ConnectMethod && !strings.HasPrefix(rawUrl, "/")

	// https代理 直接返回建立成功的标识
	tcpAddress := rawUrl

	// http代理 需要额外处理端口为80的情况
	if !justHttpsProxy {
		urlParse, err := url.Parse(rawUrl)
		if err != nil {
			log.Println("parse url error", rawUrl)
			return
		}

		tcpAddress = urlParse.Host

		if strings.Contains(urlParse.Host, ".") && !strings.Contains(urlParse.Host, ":") {
			// 判断ipv4地址或者域名没有默认端口
			tcpAddress = urlParse.Host + ":80"
		} else if strings.Contains(urlParse.Host, "[") && !strings.Contains(urlParse.Host, "]:") {
			// 判断ipv6地址没有默认端口
			tcpAddress = urlParse.Host + ":80"
		}
	}

	server, err := utils.DialTcpConnection(tcpAddress)
	if err != nil {
		log.Println(err)
		return
	}
	defer func(server net.Conn) {
		err = server.Close()
		if err != nil {
			log.Println("tcp transport close error", err)
		}
	}(server)

	clientAddr := (*conn).RemoteAddr().String()
	log.Printf("[HTTP] %s <--> %s", clientAddr, tcpAddress)

	if justHttpsProxy {
		_, err = (*conn).Write(global.ConnectedResponse)
		if err != nil {
			log.Println("Established to client error", clientAddr)
			return
		}
	} else {
		_, err = server.Write(firstBuff)
		if err != nil {
			log.Println("tcp write error", err)
			return
		}
	}

	err = utils.TransportData(&server, conn)
	if err != nil {
		log.Println("[HTTP]", err)
	}

}
