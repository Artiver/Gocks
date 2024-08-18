package socks5

import (
	"Gocks/utils"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
)

var authNone = []byte{socks5Version, 0x00}
var authUsernamePassword = []byte{socks5Version, 0x02}
var authFailed = []byte{0x01, 0x01}
var authSuccess = []byte{0x01, 0x00}
var connectFailed = []byte{socks5Version, 0x01, 0x00, addrIPv4, 0, 0, 0, 0, 0, 0}
var connectRefused = []byte{socks5Version, 0x05, 0x00, addrIPv4, 0, 0, 0, 0, 0, 0}
var connectSuccess = []byte{socks5Version, 0x00, 0x00, addrIPv4, 0, 0, 0, 0, 0, 0}

const socks5Version = 0x05
const cmdConnect = 0x01
const cmdBind = 0x02
const cmdUDP = 0x03
const addrIPv4 = 0x01
const addrIPv6 = 0x04
const addrDomain = 0x03

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
		if firstBuff[0] != socks5Version {
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
	if utils.AuthRequired {
		// 通知客户端使用用户密码认证
		_, err := (*conn).Write(authUsernamePassword)
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
		if username != utils.Config.Username || password != utils.Config.Password {
			_, err = (*conn).Write(authFailed) // 认证失败
			if err != nil {
				return err
			}
			return errors.New("authentication failed")
		}

		_, err = (*conn).Write(authSuccess) // 认证成功
		if err != nil {
			return err
		}
	} else {
		_, err := (*conn).Write(authNone) // 无需认证
		if err != nil {
			return err
		}
	}

	return nil
}

func socks5HandleRequest(conn *net.Conn) error {
	buf := make([]byte, utils.Socks5HandleBytes)

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

	if buf[0] != socks5Version {
		return errors.New("unsupported SOCKS version")
	}

	targetAddr, err := handleRequestAddr(buf)
	if err != nil {
		return err
	}

	cmd := buf[1]
	switch cmd {
	case cmdConnect:
		return handleConnect(conn, targetAddr)
	case cmdBind:
		return handleBind(conn, targetAddr)
	case cmdUDP:
		return errors.New("unsupported command")
	default:
		return errors.New("unsupported command")
	}
}

func handleRequestAddr(buf []byte) (string, error) {
	addrType := buf[3]
	var addr string
	var port uint16

	switch addrType {
	case addrIPv4:
		addr = net.IP(buf[4:8]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case addrIPv6:
		addr = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])
	case addrDomain:
		addrLen := buf[4]
		addr = string(buf[5 : 5+addrLen])
		port = binary.BigEndian.Uint16(buf[5+addrLen : 7+addrLen])
	default:
		return "", errors.New("unsupported address type")
	}
	return utils.FormatAddress(addr, port), nil
}

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

	return transportData(&targetConn, conn)
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

	return transportData(&targetConn, conn)
}

func handleUDP() {}

func transportData(source, target *net.Conn) error {
	go func() {
		_, err := io.Copy(*source, *target)
		if err != nil {
			log.Println("response to client error", err)
		}
	}()

	_, err := io.Copy(*target, *source)
	if err != nil {
		log.Println("request to server error", err)
		return err
	}

	return nil
}
