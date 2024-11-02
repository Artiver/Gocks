package udp

import (
	"Gocks/global"
	"errors"
	"log"
	"net"
	"time"
)

func Run() {
	listen, err := net.ListenPacket("udp", global.ProxyConfig.BindAddr)
	if err != nil {
		log.Fatalln("Error listening:", err)
	}
	defer func(listen net.PacketConn) {
		err = listen.Close()
		if err != nil {
			log.Println("listening close error", err)
		}
	}(listen)

	log.Println("UDP port listening", global.ProxyConfig.BindAddr)

	buffer := make([]byte, global.UdpReadBytes)

	for {
		size, clientAddr, err := listen.ReadFrom(buffer)
		if err != nil {
			log.Printf("Failed to read from client connection: %v", err)
			continue
		}

		go handleRequest(buffer, size, clientAddr, listen)
	}
}

func handleRequest(data []byte, size int, clientAddr net.Addr, listen net.PacketConn) {
	// Forward data to the server
	forwardConn, err := net.Dial("udp", global.ProxyConfig.TranAddr)
	if err != nil {
		log.Printf("Failed to forward to %s: %v", global.ProxyConfig.TranAddr, err)
		return
	}
	defer forwardConn.Close()

	// Send the data to the server
	_, err = forwardConn.Write(data[:size])
	if err != nil {
		log.Printf("Failed to write to forward connection: %v", err)
		return
	}

	// Set a read deadline to prevent indefinite waiting
	err = forwardConn.SetReadDeadline(time.Now().Add(global.UdpReceiveTimeout))
	if err != nil {
		return
	}

	// Attempt to read the server's response
	responseBuffer := make([]byte, global.UdpReadBytes)
	n, err := forwardConn.Read(responseBuffer)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && !netErr.Timeout() {
			log.Printf("Failed to read from forward connection: %v", err)
		}
		return
	}

	// Forward the server's response back to the client
	_, err = listen.WriteTo(responseBuffer[:n], clientAddr)
	if err != nil {
		log.Printf("Failed to write to client connection: %v", err)
		return
	}

	log.Printf("[UDP] %s <-> %s", clientAddr.String(), forwardConn.RemoteAddr().String())
}
