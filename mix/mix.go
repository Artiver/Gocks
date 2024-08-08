package mix

import (
	"Gocks/http"
	"Gocks/socks5"
	"Gocks/utils"
	"log"
	"net"
	"os"
)

func Run() {
	listen, err := net.Listen("tcp", utils.Config.CombineIpPort)
	if err != nil {
		log.Println("Error listening:", err)
		os.Exit(1)
	}
	defer listen.Close()

	log.Println("MIX proxy listening", utils.Config.CombineIpPort)

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go chooseProxy(conn)
	}
}

func chooseProxy(conn net.Conn) {
	buff := make([]byte, 1)
	if _, err := conn.Read(buff); err != nil {
		log.Printf("Error reading from connection: %v", err)
		return
	}

	switch buff[0] {
	case 0x05:
		socks5.HandleSocks5Connection(conn)
	default:
		http.HandleHTTPConnection(conn)
	}
}
