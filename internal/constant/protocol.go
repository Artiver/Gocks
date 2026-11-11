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

const TcpConnectTimeout = 5 * time.Second

// UDPBufferSize is large enough for any UDP payload plus the SOCKS5 header.
const UDPBufferSize = 65535

// HandshakeTimeout bounds every protocol negotiation step, including the wait
// for a client's opening message.
const HandshakeTimeout = 10 * time.Second

// UDPIdleTimeout bounds how long a SOCKS5 UDP relay waits for the next
// datagram. It is a session reclaim policy for the UDP side, independent of
// the tunnel idle timeout: a relay that never times out would keep its
// sessions and upstream sockets forever.
var UDPIdleTimeout = 300 * time.Second

// AcceptBackoff is the pause before retrying a failed Accept/ReadFrom.
const AcceptBackoff = 1 * time.Second

const BasicAuthHeader = "Proxy-Authorization"
const BasicAuthPrefix = "Basic "

const ProxyConnectKey = "Proxy-Connection"
const ProxyConnectValue = "keep-alive"

const ViaHeader = "Via"
const ViaValue = "1.1 gocks"
