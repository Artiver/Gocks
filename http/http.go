package http

import (
	"Gocks/utils"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
)

const cr = byte('\r')
const connectMethod = "CONNECT"

var connectResponse = []byte("HTTP/1.1 200 Connection established\r\n\r\n")

func Run() {
	listen, err := net.Listen("tcp", utils.Config.CombineIpPort)
	if err != nil {
		log.Println("Error listening:", err)
		log.Panic(err)
	}
	defer func(listen net.Listener) {
		err = listen.Close()
		if err != nil {
			log.Println("listening close error", err)
		}
	}(listen)

	log.Println("HTTP proxy listening", utils.Config.CombineIpPort)

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
		firstBuff = make([]byte, utils.DefaultReadBytes)
		_, err := (*conn).Read(firstBuff)
		if err != nil {
			log.Println("read http data error")
			return
		}
	}

	index := bytes.IndexByte(firstBuff, cr)
	if index == -1 {
		log.Println("not http proxy request")
		return
	}
	firstLine := string(firstBuff[:index])

	var method, rawUrl string
	_, err := fmt.Sscanf(firstLine, "%s %s", &method, &rawUrl)
	if err != nil {
		log.Println("parse http request header error", firstLine)
		return
	}

	// CONNECT www.google.com:443 HTTP/1.1
	justHttpsProxy := method == connectMethod && !strings.HasPrefix(rawUrl, "/")

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

	server, err := net.DialTimeout("tcp", tcpAddress, utils.TcpConnectTimeout)
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
		_, err = (*conn).Write(connectResponse)
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

	go func() {
		_, err = io.Copy(server, *conn)
		if err != nil {
			log.Println("response to client error", clientAddr)
			return
		}
	}()

	_, err = io.Copy(*conn, server)
	if err != nil {
		log.Println("request to server error", tcpAddress)
		return
	}
}
