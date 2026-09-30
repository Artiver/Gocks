package socks5

import (
	"encoding/binary"
	"io"
)

// UDPHeader is the SOCKS5 UDP request header:
//
//	+-----+------+------+----------+----------+----------+
//	| RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+-----+------+------+----------+----------+----------+
//	|  2  |  1   |  1   | Variable |    2     | Variable |
//	+-----+------+------+----------+----------+----------+
type UDPHeader struct {
	Rsv  uint16
	Frag byte
	Addr *Addr
}

// NewUDPHeader returns a UDP header.
func NewUDPHeader(rsv uint16, frag byte, addr *Addr) *UDPHeader {
	return &UDPHeader{Rsv: rsv, Frag: frag, Addr: addr}
}

// Unmarshal parses a header from b and returns the number of bytes consumed.
func (h *UDPHeader) Unmarshal(b []byte) (int, error) {
	if len(b) < 3 {
		return 0, io.ErrUnexpectedEOF
	}
	h.Rsv = binary.BigEndian.Uint16(b[:2])
	h.Frag = b[2]

	if h.Addr == nil {
		h.Addr = &Addr{}
	}
	n, err := h.Addr.Decode(b[3:])
	if err != nil {
		return 0, err
	}
	return 3 + n, nil
}

// Marshal returns the wire representation of the header.
func (h *UDPHeader) Marshal() ([]byte, error) {
	addr := h.Addr
	if addr == nil {
		addr = &Addr{Type: AddrIPv4}
	}
	buf := make([]byte, 3+addr.Length())
	binary.BigEndian.PutUint16(buf[:2], h.Rsv)
	buf[2] = h.Frag
	if _, err := addr.Encode(buf[3:]); err != nil {
		return nil, err
	}
	return buf, nil
}

// UDPDatagram is a SOCKS5 UDP datagram: a header followed by a payload.
type UDPDatagram struct {
	Header *UDPHeader
	Data   []byte
}

// NewUDPDatagram returns a datagram with the given header and payload.
func NewUDPDatagram(header *UDPHeader, data []byte) *UDPDatagram {
	return &UDPDatagram{Header: header, Data: data}
}

// Unmarshal parses a datagram from b; the returned payload aliases b.
func (d *UDPDatagram) Unmarshal(b []byte) error {
	if d.Header == nil {
		d.Header = &UDPHeader{}
	}
	n, err := d.Header.Unmarshal(b)
	if err != nil {
		return err
	}
	d.Data = b[n:]
	return nil
}

// Marshal returns the wire representation of the datagram.
func (d *UDPDatagram) Marshal() ([]byte, error) {
	header := d.Header
	if header == nil {
		header = &UDPHeader{}
	}
	head, err := header.Marshal()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(head)+len(d.Data))
	buf = append(buf, head...)
	buf = append(buf, d.Data...)
	return buf, nil
}
