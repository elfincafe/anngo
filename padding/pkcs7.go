package padding

import (
	"bytes"
	"errors"
)

type PKCS7 struct {
	name   string
	buffer []byte
}

func NewPkcs7(buffer []byte) *PKCS7 {
	p := new(PKCS7)
	copy(p.buffer, buffer)
	return p
}

func (p *PKCS7) Pad(BlockSize int) ([]byte, error) {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return p.buffer, nil
	}
	// Padding
	pad := bytes.Repeat([]byte{byteMap1[size]}, size)
	p.buffer = append(p.buffer, pad...)

	return p.buffer, nil
}

func (p *PKCS7) Unpad(BlockSize int) ([]byte, error) {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return p.buffer, nil
	}
	// Unpadding
	b := p.buffer[len(p.buffer)-1]
	if _, ok := byteMap2[b]; !ok {
		return nil, errors.New("Can't find PKCS7 padding")
	}
	idx := bytes.Index(p.buffer, bytes.Repeat([]byte{b}, size))
	p.buffer = p.buffer[:idx]
	return p.buffer, nil
}

func (p *PKCS7) Name() string {
	return p.name
}
