package constant

var ResponseAuthNone = []byte{Socks5Version, 0x00}
var ResponseAuthUsernamePassword = []byte{Socks5Version, 0x02}
var AuthFailed = []byte{0x01, 0x01}
var AuthSuccess = []byte{0x01, 0x00}
var ConnectFailed = []byte{Socks5Version, 0x01, 0x00, AddrIPv4, 0, 0, 0, 0, 0, 0}
var ConnectRefused = []byte{Socks5Version, 0x05, 0x00, AddrIPv4, 0, 0, 0, 0, 0, 0}
var ConnectSuccess = []byte{Socks5Version, 0x00, 0x00, AddrIPv4, 0, 0, 0, 0, 0, 0}

var ClientInitialReq = []byte{Socks5Version, 0x02, 0x00, 0x02}

func NewClientRequestIPv4() []byte {
	return []byte{Socks5Version, CmdConnect, 0x00, AddrIPv4}
}

func NewClientRequestIPv6() []byte {
	return []byte{Socks5Version, CmdConnect, 0x00, AddrIPv6}
}

func NewClientRequestDomain() []byte {
	return []byte{Socks5Version, CmdConnect, 0x00, AddrDomain}
}

const Socks5Version = 0x05
const CmdConnect = 0x01
const CmdBind = 0x02
const CmdUDP = 0x03
const AddrIPv4 = 0x01
const AddrIPv6 = 0x04
const AddrDomain = 0x03
