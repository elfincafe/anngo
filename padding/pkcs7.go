package padding

import (
	"bytes"
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

func (p *PKCS7) Pad(BlockSize int) error {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return nil
	}
	// Padding
	pad := bytes.Repeat([]byte{byteMap1[size]}, size)
	p.buffer = append(p.buffer, pad...)

	return nil
}

func (p *PKCS7) Unpad(BlockSize int) error {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return nil
	}
	// Unpadding
	b := p.buffer[len(p.buffer)-1]
	if _, ok := byteMap2[b]; !ok {
		return nil
	}
	idx := bytes.Index(p.buffer, bytes.Repeat([]byte{b}, size))
	p.buffer = p.buffer[:idx]
	return nil
}

func (p *PKCS7) Name() string {
	return p.name
}
