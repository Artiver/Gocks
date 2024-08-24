package global

import (
	"time"
)

const TCP = "tcp"
const HTTP = "http"
const Socks5 = "socks5"

const ConnectMethod = "CONNECT"
const DefaultReadBytes = 512
const Socks5HandleBytes = 256
const TcpConnectTimeout = 5 * time.Second

const BasicAuthHeader = "Proxy-Authorization"
const BasicAuthPrefix = "Basic "

const ProxyConnectKey = "Proxy-Connection"
const ProxyConnectValue = "keep-alive"

const CR = byte('\r')
