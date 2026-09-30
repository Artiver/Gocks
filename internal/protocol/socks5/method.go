package socks5

import "io"

// ReadMethods reads the method selection message:
//
//	+----+----------+----------+
//	|VER | NMETHODS | METHODS  |
//	+----+----------+----------+
//	| 1  |    1     | 1 to 255 |
//	+----+----------+----------+
//
// It returns the authentication methods offered by the client.
func ReadMethods(r io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if header[0] != Version {
		return nil, ErrBadVersion
	}
	if header[1] == 0 {
		return nil, ErrBadMethod
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, err
	}
	return methods, nil
}

// WriteMethod writes the method selection reply:
//
//	+----+--------+
//	|VER | METHOD |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
func WriteMethod(method byte, w io.Writer) error {
	_, err := w.Write([]byte{Version, method})
	return err
}

// HasMethod reports whether methods contains m.
func HasMethod(methods []byte, m byte) bool {
	for _, method := range methods {
		if method == m {
			return true
		}
	}
	return false
}
