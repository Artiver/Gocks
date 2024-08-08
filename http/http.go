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

func Run(ip string, port uint16, username, password string) {
	formatInfo := utils.FormatAddress(ip, port)

	l, err := net.Listen("tcp", formatInfo)
	if err != nil {
		log.Panic(err)
	}

	log.Println("HTTP proxy listening", formatInfo)

	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go handleClientRequest(client)
	}
}

func handleClientRequest(client net.Conn) {
	if client == nil {
		return
	}
	defer client.Close()

	b := make([]byte, 1024)
	_, err := client.Read(b)
	if err != nil {
		log.Println("read client data error")
		return
	}

	var method, host string
	firstLine := string(b[:bytes.IndexByte(b, cr)])

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
		server.Write(b)
	}

	go io.Copy(server, client)
	io.Copy(client, server)
}
