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
			log.Panic(err)
		}

		go HandleHTTPConnection(conn, nil)
	}
}

func HandleHTTPConnection(client net.Conn, firstBuff []byte) {
	if client == nil {
		return
	}
	defer client.Close()

	if firstBuff == nil {
		firstBuff = make([]byte, 512)
		_, err := client.Read(firstBuff)
		if err != nil {
			log.Println("read client data error")
			return
		}
	}

	index := bytes.IndexByte(firstBuff, cr)
	if index == -1 {
		log.Println("not http proxy request")
		return
	}
	firstLine := string(firstBuff[:index])

	var method, host string
	fmt.Sscanf(firstLine, "%s %s", &method, &host)
	hostPortURL, err := url.Parse(host)
	if err != nil {
		log.Println("parse client url error")
		return
	}

	var address string
	if hostPortURL.Opaque == "443" {
		//https访问
		address = hostPortURL.Scheme + ":443"
	} else {
		//http访问
		if strings.Index(hostPortURL.Host, ":") == -1 {
			//host不带端口， 默认80
			address = hostPortURL.Host + ":80"
		} else {
			address = hostPortURL.Host
		}
	}

	clientAddr := client.RemoteAddr().String()
	log.Printf("%s <--> %s", clientAddr, firstLine)

	server, err := net.Dial("tcp", address)
	if err != nil {
		log.Println("dial tcp error " + address)
		return
	}

	if method == connectMethod {
		client.Write(connectResponse)
	} else {
		server.Write(firstBuff)
	}

	go io.Copy(server, client)
	io.Copy(client, server)
}
