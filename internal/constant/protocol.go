package constant

import (
	"time"
)

// Endpoint schemes accepted by -L and -F.
const TCP = "tcp"
const UDP = "udp"
const HTTP = "http"
const Socks5 = "socks5"

const ConnectMethod = "CONNECT"

// DefaultReadBytes is the prefix the mixed-mode dispatcher reads to tell HTTP
// and SOCKS5 apart.
const DefaultReadBytes = 512

const TcpConnectTimeout = 5 * time.Second
const UdpReceiveTimeout = 3 * time.Second

// HandshakeTimeout bounds every protocol negotiation step, including the wait
// for a client's opening message.
const HandshakeTimeout = 10 * time.Second

// IdleTimeout bounds how long a connection may make no progress. It is used as
// a read deadline before every read, both while a handshake is in flight and
// while data is being relayed, so an idle tunnel is closed after 5 minutes
// rather than held open forever.
const IdleTimeout = 300 * time.Second

// AcceptBackoff is the pause before retrying a failed Accept/ReadFrom.
const AcceptBackoff = 1 * time.Second

const BasicAuthHeader = "Proxy-Authorization"
const BasicAuthPrefix = "Basic "

const ProxyConnectKey = "Proxy-Connection"
const ProxyConnectValue = "keep-alive"

const ViaHeader = "Via"
const ViaValue = "1.1 gocks"
