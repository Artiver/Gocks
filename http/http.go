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
	defer listen.Close()

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
	defer (*conn).Close()

	if firstBuff == nil {
		firstBuff = make([]byte, 512)
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
	fmt.Sscanf(firstLine, "%s %s", &method, &rawUrl)

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
			tcpAddress = urlParse.Host + ":80"
		}
	}

	server, err := net.DialTimeout("tcp", tcpAddress, utils.TcpConnectTimeout)
	if err != nil {
		log.Println(err)
		return
	}

	clientAddr := (*conn).RemoteAddr().String()
	log.Printf("[HTTP] %s <--> %s", clientAddr, tcpAddress)

	if justHttpsProxy {
		(*conn).Write(connectResponse)
	} else {
		server.Write(firstBuff)
	}

	go io.Copy(server, *conn)
	io.Copy(*conn, server)
}
