package socks5

import (
	"Gocks/utils"
	"encoding/binary"
	"errors"
	"log"
	"net"
)

func handleConnect(conn *net.Conn, targetAddr string) error {
	targetConn, err := net.DialTimeout("tcp", targetAddr, utils.TcpConnectTimeout)

	// The server evaluates the request, and returns a reply formed as follows:
	//
	//    +----+-----+-------+------+----------+----------+
	//    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	//    +----+-----+-------+------+----------+----------+
	//    | 1  |  1  | X'00' |  1   | Variable |    2     |
	//    +----+-----+-------+------+----------+----------+

	if err != nil {
		_, err = (*conn).Write(connectFailed)
		if err != nil {
			return err
		}
		return errors.New("dial tcp " + targetAddr)
	}
	defer func(targetConn net.Conn) {
		err = targetConn.Close()
		if err != nil {
			log.Println("target connection close error", err)
		}
	}(targetConn)

	clientAddr := (*conn).RemoteAddr().String()
	log.Printf("[SOCKS5] [CONNECT] %s <--> %s", clientAddr, targetAddr)

	_, err = (*conn).Write(connectSuccess)
	if err != nil {
		return err
	}

	return utils.TransportData(&targetConn, conn)
}

func handleBind(conn *net.Conn, targetAddr string) error {
	listener, err := net.Listen("tcp", targetAddr)
	if err != nil {
		(*conn).Write(connectRefused)
		return err
	}
	defer listener.Close()

	localAddr := listener.Addr().(*net.TCPAddr)
	resp := []byte{socks5Version, 0, 0, addrIPv4}
	resp = append(resp, localAddr.IP.To4()...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(localAddr.Port))
	resp = append(resp, portBuf...)
	if _, err = (*conn).Write(resp); err != nil {
		return err
	}

	targetConn, err := listener.Accept()
	if err != nil {
		(*conn).Write(connectFailed)
		return err
	}
	defer targetConn.Close()

	resp = []byte{socks5Version, 0, 0, addrIPv4}
	resp = append(resp, localAddr.IP.To4()...)
	binary.BigEndian.PutUint16(portBuf, uint16(localAddr.Port))
	resp = append(resp, portBuf...)
	if _, err = (*conn).Write(resp); err != nil {
		return err
	}

	clientAddr := (*conn).RemoteAddr().String()
	log.Printf("[SOCKS5] [BIND] %s <--> %s", clientAddr, targetAddr)

	return utils.TransportData(&targetConn, conn)
}

func handleUDPAssociate() {}
