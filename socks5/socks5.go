package socks5

import (
	"Gocks/utils"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

var chooseAuthMethod = []byte{0x05, 0x02}
var authFailed = []byte{0x01, 0x01}
var authSuccess = []byte{0x01, 0x00}
var authNeedNot = []byte{0x05, 0x00}
var dealFailed = []byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
var dealSuccess = []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}

func Run() {
	listen, err := net.Listen("tcp", utils.Config.CombineIpPort)
	if err != nil {
		log.Println("Error listening:", err)
		log.Panic(err)
	}
	defer func(listen net.Listener) {
		err = listen.Close()
		if err != nil {
			log.Println("listening close error", err)
		}
	}(listen)

	log.Println("SOCKS5 proxy listening", utils.Config.CombineIpPort)

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go HandleSocks5Connection(&conn, nil)
	}
}

func HandleSocks5Connection(conn *net.Conn, firstBuff []byte) {
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Println("connection close error", err)
		}
	}(*conn)

	if err := socks5Handshake(conn, firstBuff); err != nil {
		log.Println("Handshake error:", err)
		return
	}

	if err := socks5HandleRequest(conn); err != nil {
		log.Println("Request handling error:", err)
	}
}

func socks5Handshake(conn *net.Conn, firstBuff []byte) error {
	if firstBuff == nil {
		firstBuff = make([]byte, utils.Socks5HandleBytes)
		n, err := (*conn).Read(firstBuff)
		if err != nil || n < 2 {
			return errors.New("failed to read from client")
		}
		if firstBuff[0] != 0x05 {
			return errors.New("unsupported SOCKS version")
		}
	}

	if utils.AuthRequired {
		// 通知客户端使用用户密码认证
		_, err := (*conn).Write(chooseAuthMethod)
		if err != nil {
			return err
		}

		// 用户名密码认证
		n, err := (*conn).Read(firstBuff)
		if err != nil || n < 2 {
			return errors.New("failed to read authentication request")
		}

		if firstBuff[0] != 0x01 {
			return errors.New("unsupported auth version")
		}

		usernameLen := int(firstBuff[1])
		username := string(firstBuff[2 : 2+usernameLen])

		passwordLen := int(firstBuff[2+usernameLen])
		password := string(firstBuff[3+usernameLen : 3+usernameLen+passwordLen])

		if username != utils.Config.Username || password != utils.Config.Password {
			_, err = (*conn).Write(authFailed)
			if err != nil {
				return err
			}
			return errors.New("authentication failed") // 认证失败
		}

		_, err = (*conn).Write(authSuccess) // 认证成功
		if err != nil {
			return err
		}
	} else {
		_, err := (*conn).Write(authNeedNot) // 无需认证
		if err != nil {
			return err
		}
	}

	return nil
}

func socks5HandleRequest(conn *net.Conn) error {
	buf := make([]byte, utils.Socks5HandleBytes)

	// 读取客户端请求
	n, err := (*conn).Read(buf)
	if err != nil || n < 7 {
		return errors.New("failed to read request")
	}

	if buf[0] != 0x05 {
		return errors.New("unsupported SOCKS version")
	}

	cmd := buf[1]
	addrType := buf[3]
	var addr string
	var port uint16

	switch addrType {
	case 0x01: // IPv4
		addr = net.IP(buf[4:8]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case 0x03: // 域名
		addrLen := buf[4]
		addr = string(buf[5 : 5+addrLen])
		port = binary.BigEndian.Uint16(buf[5+addrLen : 7+addrLen])
	case 0x04: // IPv6
		addr = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])
	default:
		return errors.New("unsupported address type")
	}

	if cmd != 0x01 {
		return errors.New("unsupported command")
	}

	targetConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", addr, port), utils.TcpConnectTimeout)
	if err != nil {
		_, err = (*conn).Write(dealFailed)
		if err != nil {
			return err
		}
		return errors.New("dial tcp " + utils.FormatAddress(addr, port))
	}
	defer func(targetConn net.Conn) {
		err = targetConn.Close()
		if err != nil {
			log.Println("target connection close error", err)
		}
	}(targetConn)

	clientAddr := (*conn).RemoteAddr().String()
	log.Printf("[SOCKS5] %s <--> %s:%d", clientAddr, addr, port)

	_, err = (*conn).Write(dealSuccess)
	if err != nil {
		return err
	}

	go func() {
		_, err = io.Copy(targetConn, *conn)
		if err != nil {
			log.Println("response to client error", clientAddr)
		}
	}()

	_, err = io.Copy(*conn, targetConn)
	if err != nil {
		log.Println("request to server error", clientAddr)
		return err
	}

	return nil
}
