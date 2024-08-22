package global

import (
	"time"
)

const Socks5 = "socks5"
const HTTP = "http"

const ConnectMethod = "CONNECT"
const Socks5HandleBytes = 256
const DefaultReadBytes = 512
const TcpConnectTimeout = 5 * time.Second

const BasicAuthHeader = "Proxy-Authorization"
const BasicAuthPrefix = "Basic "

const ProxyConnectKey = "Proxy-Connection"
const ProxyConnectValue = "keep-alive"

const CR = byte('\r')
