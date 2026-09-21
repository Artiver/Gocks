package tcp

import (
	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/tunnel"
	"log"
	"net"
)

func Run() {
	listen, err := net.Listen("tcp", config.ProxyConfig.BindAddr)
	if err != nil {
		log.Fatalln("Error listening:", err)
	}
	defer func(listen net.Listener) {
		err = listen.Close()
		if err != nil {
			log.Println("listening close error", err)
		}
	}(listen)

	log.Println("TCP port listening", config.ProxyConfig.BindAddr)

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}

		go handleConnection(&conn)
	}
}

func handleConnection(src *net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	dst, err := net.DialTimeout("tcp", config.ProxyConfig.TranAddr, constant.TcpConnectTimeout)
	defer (*src).Close()

	if err != nil {
		log.Println("dial tcp error which", config.ProxyConfig.TranAddr)
		return
	}
	defer dst.Close()

	err = tunnel.TransportData(src, &dst)
	if err != nil {
		log.Println("transport data error", err)
	}

	log.Printf("[TCP] %s <-> %s", (*src).RemoteAddr().String(), dst.RemoteAddr().String())
}
