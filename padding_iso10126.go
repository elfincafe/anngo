package anngo

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
)

type ISO10126 struct {
	name string
}

func NewIso10126() *ISO10126 {
	p := new(ISO10126)
	p.name = "ISO 10126"
	return p
}

func (p *ISO10126) Pad(b []byte) ([]byte, error) {
	// check length
	length := len(b)
	if length%aes.BlockSize == 0 {
		return b, nil
	}
	// Padding
	size := byte(aes.BlockSize - length%aes.BlockSize)
	buffer := make([]byte, length+int(size))
	rand.Read(buffer)
	copy(buffer, b)
	buffer[length-1] = size

	return buffer, nil
}

func (p *ISO10126) Unpad(b []byte) ([]byte, error) {
	// check length
	length := len(b)
	if length%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	// Unpadding
	lastByte := b[len(b)-1]
	if lastByte > 0x0f {
		return b, nil
	}
	s := length - int(lastByte)

	return b[:s], nil
}

func (p *ISO10126) Name() string {
	return p.name
}
