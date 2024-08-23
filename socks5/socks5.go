package socks5

import (
	"Gocks/global"
	"Gocks/utils"
	"encoding/binary"
	"errors"
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

	log.Println("SOCKS5 proxy listening", global.ProxyConfig.BindAddr)

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
		firstBuff = make([]byte, global.Socks5HandleBytes)

		// The client connects to the server, and sends a version identifier/method selection message:
		//
		//     +----+----------+----------+
		//     |VER | NMETHODS | METHODS  |
		//     +----+----------+----------+
		//     | 1  |    1     | 1 to 255 |
		//     +----+----------+----------+

		n, err := (*conn).Read(firstBuff)
		if err != nil || n < 2 {
			return errors.New("failed to read from client")
		}
		if firstBuff[0] != global.Socks5Version {
			return errors.New("unsupported SOCKS version")
		}
	}

	// The server selects from one of the methods given in METHODS, and sends a METHOD selection message:
	//
	//     +----+--------+
	//     |VER | METHOD |
	//     +----+--------+
	//     | 1  |   1    |
	//     +----+--------+

	if global.ProxyConfig.Socks5Auth != nil {
		// 通知客户端使用用户密码认证
		_, err := (*conn).Write(global.ResponseAuthUsernamePassword)
		if err != nil {
			return err
		}

		// This begins with the client producing a Username/Password request:
		//
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+

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

		// The server verifies the supplied UNAME and PASSWD, and sends the following response:
		//
		// +----+--------+
		// |VER | STATUS |
		// +----+--------+
		// | 1  |   1    |
		// +----+--------+

		if username != global.ProxyConfig.Username || password != global.ProxyConfig.Password {
			_, err = (*conn).Write(global.AuthFailed)
			if err != nil {
				return err
			}
			return errors.New("authentication failed")
		}

		_, err = (*conn).Write(global.AuthSuccess)
		if err != nil {
			return err
		}
	} else {
		_, err := (*conn).Write(global.ResponseAuthNone)
		if err != nil {
			return err
		}
	}

	return nil
}

func socks5HandleRequest(conn *net.Conn) error {
	buf := make([]byte, global.Socks5HandleBytes)

	// The SOCKS request is formed as follows:
	//
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+

	n, err := (*conn).Read(buf)
	if err != nil || n < 7 {
		return errors.New("failed to read request")
	}

	if buf[0] != global.Socks5Version {
		return errors.New("unsupported SOCKS version")
	}

	targetAddr, err := handleRequestAddr(buf)
	if err != nil {
		return err
	}

	cmd := buf[1]
	switch cmd {
	case global.CmdConnect:
		return handleConnect(conn, targetAddr)
	case global.CmdBind:
		return handleBind(conn, targetAddr)
	case global.CmdUDP:
		return handleUDPAssociate(conn)
	default:
		return errors.New("unsupported command")
	}
}

func handleRequestAddr(buf []byte) (string, error) {
	addrType := buf[3]
	var addr string
	var port uint16

	switch addrType {
	case global.AddrIPv4:
		addr = net.IP(buf[4:8]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case global.AddrIPv6:
		addr = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])
	case global.AddrDomain:
		addrLen := buf[4]
		addr = string(buf[5 : 5+addrLen])
		port = binary.BigEndian.Uint16(buf[5+addrLen : 7+addrLen])
	default:
		return "", errors.New("unsupported address type")
	}
	return utils.FormatAddress(addr, port), nil
}
