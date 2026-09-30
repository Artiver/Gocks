package socks5

import (
	"io"
)

// Reply is a SOCKS5 reply:
//
//	+----+-----+-------+------+----------+----------+
//	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  | X'00' |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
type Reply struct {
	Rep  byte
	Addr *Addr
}

// NewReply returns a reply with the given code and bound address.
func NewReply(rep byte, addr *Addr) *Reply {
	return &Reply{Rep: rep, Addr: addr}
}

// ReadReply reads exactly one reply. As with ReadRequest, trailing bytes are
// left unread so a client can safely use a buffered reader.
func ReadReply(r io.Reader) (*Reply, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if header[0] != Version {
		return nil, ErrBadVersion
	}

	addr := &Addr{Type: header[3]}
	if _, err := addr.readBody(r); err != nil {
		return nil, err
	}
	return &Reply{Rep: header[1], Addr: addr}, nil
}

// Write encodes the reply. A nil address is encoded as 0.0.0.0:0.
func (rep *Reply) Write(w io.Writer) error {
	addr := rep.Addr
	if addr == nil {
		addr = &Addr{Type: AddrIPv4}
	}
	buf := make([]byte, 3+addr.Length())
	buf[0] = Version
	buf[1] = rep.Rep
	buf[2] = 0x00
	if _, err := addr.Encode(buf[3:]); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}
