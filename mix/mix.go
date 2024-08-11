package mix

import (
	"Gocks/http"
	"Gocks/socks5"
	"Gocks/utils"
	"log"
	"net"
)

func Run() {
	listen, err := net.Listen("tcp", utils.Config.CombineIpPort)
	if err != nil {
		log.Println("Error listening:", err)
		log.Panic(err)
	}
	defer listen.Close()

	log.Println("MIX proxy listening", utils.Config.CombineIpPort)

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go chooseProxy(&conn)
	}
}

func chooseProxy(conn *net.Conn) {
	buff := make([]byte, utils.DefaultReadBytes)
	if _, err := (*conn).Read(buff); err != nil {
		log.Printf("Error reading from connection: %v", err)
		return
	}

	switch buff[0] {
	case 0x05:
		go socks5.HandleSocks5Connection(conn, buff)
	default:
		go http.HandleHTTPConnection(conn, buff)
	}
}
