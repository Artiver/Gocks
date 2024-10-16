package tcp

import (
	"Gocks/global"
	"Gocks/utils"
	"log"
	"net"
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

	log.Println("TCP port listening", global.ProxyConfig.BindAddr)

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
	dst, err := net.Dial("tcp", global.ProxyConfig.TranAddr)
	defer dst.Close()
	defer (*src).Close()

	if err != nil {
		log.Println("dia tcp error which", global.ProxyConfig.TranAddr)
		return
	}

	err = utils.TransportData(src, &dst)
	if err != nil {
		log.Println("transport data error", err)
	}

	log.Printf("[TCP] %s <-> %s", (*src).RemoteAddr().String(), dst.RemoteAddr().String())
}
