package socks5

import (
	"encoding/binary"
	"fmt"
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

// ReadFrom reads RSV, FRAG, ATYP and the address.
func (h *UDPHeader) ReadFrom(r io.Reader) (int64, error) {
	var b [3]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	h.Rsv = binary.BigEndian.Uint16(b[:2])
	h.Frag = b[2]

	if h.Addr == nil {
		h.Addr = &Addr{}
	}
	n, err := h.Addr.ReadFrom(r)
	return 3 + n, err
}

// WriteTo writes RSV, FRAG, ATYP and the address.
func (h *UDPHeader) WriteTo(w io.Writer) (int64, error) {
	var b [3]byte
	binary.BigEndian.PutUint16(b[:2], h.Rsv)
	b[2] = h.Frag
	nn, err := w.Write(b[:])
	if err != nil {
		return int64(nn), err
	}

	addr := h.Addr
	if addr == nil {
		addr = &Addr{Type: AddrIPv4}
	}
	n, err := addr.WriteTo(w)
	return int64(nn) + n, err
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

func (h *UDPHeader) String() string {
	addr := h.Addr
	if addr == nil {
		addr = &Addr{}
	}
	return fmt.Sprintf("%d %d %s", h.Rsv, h.Frag, addr.String())
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

// ReadFrom reads a datagram from r. When the reserved field is non-zero the
// payload length is taken from it (the gost UDP-over-TCP extension);
// otherwise r is drained, so r must be scoped to a single datagram.
func (d *UDPDatagram) ReadFrom(r io.Reader) (int64, error) {
	if d.Header == nil {
		d.Header = &UDPHeader{}
	}
	n, err := d.Header.ReadFrom(r)
	if err != nil {
		return n, err
	}

	if d.Header.Rsv > 0 {
		data := make([]byte, int(d.Header.Rsv))
		if _, err := io.ReadFull(r, data); err != nil {
			return n, err
		}
		d.Data = data
		return n + int64(len(data)), nil
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return n, err
	}
	d.Data = data
	return n + int64(len(data)), nil
}

// WriteTo writes the datagram to w.
func (d *UDPDatagram) WriteTo(w io.Writer) (int64, error) {
	header := d.Header
	if header == nil {
		header = &UDPHeader{}
	}
	n, err := header.WriteTo(w)
	if err != nil {
		return n, err
	}
	nn, err := w.Write(d.Data)
	return n + int64(nn), err
}
