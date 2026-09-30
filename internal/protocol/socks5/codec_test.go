package socks5

import "io"

// oneByteReader yields one byte per Read to emulate TCP fragmentation.
type oneByteReader struct {
	data []byte
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

// chunkReader yields at most n bytes per Read.
type chunkReader struct {
	data []byte
	n    int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if len(p) > r.n {
		p = p[:r.n]
	}
	if len(p) > len(r.data) {
		p = p[:len(r.data)]
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
