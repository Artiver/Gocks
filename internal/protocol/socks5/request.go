package socks5

import (
	"fmt"
	"io"
)

// Request is a SOCKS5 request:
//
//	+----+-----+-------+------+----------+----------+
//	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  | X'00' |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
type Request struct {
	Cmd  byte
	Addr *Addr
}

// NewRequest returns a request for the given command and target address.
func NewRequest(cmd byte, addr *Addr) *Request {
	return &Request{Cmd: cmd, Addr: addr}
}

// ReadRequest reads exactly one request. Bytes that follow the request are
// left unread, so a buffered or prefixed reader keeps any pipelined payload
// (for example data sent right after CONNECT) intact.
func ReadRequest(r io.Reader) (*Request, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if header[0] != Version {
		return nil, ErrBadVersion
	}
	if header[2] != 0x00 {
		return nil, ErrBadFormat
	}

	addr := &Addr{Type: header[3]}
	if _, err := addr.readBody(r); err != nil {
		return nil, err
	}
	return &Request{Cmd: header[1], Addr: addr}, nil
}

// Write encodes the request.
func (req *Request) Write(w io.Writer) error {
	addr := req.Addr
	if addr == nil {
		addr = &Addr{Type: AddrIPv4}
	}
	buf := make([]byte, 3+addr.Length())
	buf[0] = Version
	buf[1] = req.Cmd
	buf[2] = 0x00
	if _, err := addr.Encode(buf[3:]); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}

func (req *Request) String() string {
	addr := req.Addr
	if addr == nil {
		addr = &Addr{}
	}
	return fmt.Sprintf("%d %d %s", Version, req.Cmd, addr.String())
}
