package socks5

import (
	"io"
)

// UserPassRequest is the username/password authentication request:
//
//	+----+------+----------+------+----------+
//	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//	+----+------+----------+------+----------+
//	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//	+----+------+----------+------+----------+
type UserPassRequest struct {
	Version  byte
	Username string
	Password string
}

// NewUserPassRequest returns a request with the given credentials.
func NewUserPassRequest(ver byte, username, password string) *UserPassRequest {
	return &UserPassRequest{
		Version:  ver,
		Username: username,
		Password: password,
	}
}

// ReadUserPassRequest reads a complete username/password request. Reads are
// framed exactly, so a fragmented TCP segment cannot be mistaken for a
// malformed request.
func ReadUserPassRequest(r io.Reader) (*UserPassRequest, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if header[0] != UserPassVersion {
		return nil, ErrBadVersion
	}

	req := &UserPassRequest{Version: header[0]}

	ulen := int(header[1])
	if ulen > 0 {
		username := make([]byte, ulen)
		if _, err := io.ReadFull(r, username); err != nil {
			return nil, err
		}
		req.Username = string(username)
	}

	var plenBuf [1]byte
	if _, err := io.ReadFull(r, plenBuf[:]); err != nil {
		return nil, err
	}
	plen := int(plenBuf[0])
	if plen > 0 {
		password := make([]byte, plen)
		if _, err := io.ReadFull(r, password); err != nil {
			return nil, err
		}
		req.Password = string(password)
	}

	return req, nil
}

// Write encodes the request.
func (req *UserPassRequest) Write(w io.Writer) error {
	if len(req.Username) > 255 || len(req.Password) > 255 {
		return ErrBadFormat
	}
	buf := make([]byte, 0, 2+len(req.Username)+1+len(req.Password))
	buf = append(buf, req.Version, byte(len(req.Username)))
	buf = append(buf, req.Username...)
	buf = append(buf, byte(len(req.Password)))
	buf = append(buf, req.Password...)
	_, err := w.Write(buf)
	return err
}

// UserPassResponse is the username/password authentication reply:
//
//	+----+--------+
//	|VER | STATUS |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
type UserPassResponse struct {
	Version byte
	Status  byte
}

// NewUserPassResponse returns a response with the given status.
func NewUserPassResponse(ver, status byte) *UserPassResponse {
	return &UserPassResponse{
		Version: ver,
		Status:  status,
	}
}

// ReadUserPassResponse reads a complete username/password response.
func ReadUserPassResponse(r io.Reader) (*UserPassResponse, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, err
	}
	if b[0] != UserPassVersion {
		return nil, ErrBadVersion
	}
	return &UserPassResponse{Version: b[0], Status: b[1]}, nil
}

// Write encodes the response.
func (res *UserPassResponse) Write(w io.Writer) error {
	_, err := w.Write([]byte{res.Version, res.Status})
	return err
}
