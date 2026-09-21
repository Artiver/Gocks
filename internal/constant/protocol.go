package constant

import (
	"time"
)

const TCP = "tcp"
const UDP = "udp"
const HTTP = "http"
const Socks5 = "socks5"

const ConnectMethod = "CONNECT"
const UdpReadBytes = 1024
const DefaultReadBytes = 512
const Socks5HandleBytes = 256
const TcpConnectTimeout = 5 * time.Second
const UdpReceiveTimeout = 3 * time.Second
const HandshakeTimeout = 10 * time.Second
const IdleTimeout = 300 * time.Second
const MaxHeaderBytes = 1 << 20
const ForwardDialTimeout = 10 * time.Second

const BasicAuthHeader = "Proxy-Authorization"
const BasicAuthPrefix = "Basic "

const ProxyConnectKey = "Proxy-Connection"
const ProxyConnectValue = "keep-alive"

const ViaHeader = "Via"
const ViaValue = "1.1 gocks"
const ProxyAgentHeader = "Proxy-Agent"
const ProxyAgentValue = "gocks"

const CR = byte('\r')
