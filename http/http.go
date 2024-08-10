package http

import (
	"Gocks/utils"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
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

		go HandleHTTPConnection(conn, nil)
	}
}

func HandleHTTPConnection(conn net.Conn, firstBuff []byte) {
	if conn == nil {
		return
	}
	defer conn.Close()

	if firstBuff == nil {
		firstBuff = make([]byte, 512)
		_, err := conn.Read(firstBuff)
		if err != nil {
			log.Println("read conn data error")
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

	server, err := net.Dial("tcp", host)
	if err != nil {
		log.Println("dial tcp error " + host)
		return
	}

	clientAddr := conn.RemoteAddr().String()
	log.Printf("%s <--> %s", clientAddr, firstLine)

	if method == connectMethod {
		conn.Write(connectResponse)
	} else {
		server.Write(firstBuff)
	}

	go io.Copy(server, conn)
	io.Copy(conn, server)
}
