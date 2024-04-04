package padding

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
)

type ISO10126 struct {
	name   string
	buffer []byte
}

func NewIso10126(buffer []byte) *ISO10126 {
	p := new(ISO10126)
	p.name = "ISO10126"
	p.buffer = make([]byte, len(buffer))
	copy(p.buffer, buffer)
	return p
}

func (p *ISO10126) Pad() ([]byte, error) {
	// check length
	length := len(p.buffer)
	if length%aes.BlockSize == 0 {
		return p.buffer, nil
	}
	// Padding
	size := byte(aes.BlockSize - len(p.buffer)%aes.BlockSize)
	pad := make([]byte, size)
	rand.Read(pad)
	pad[int(size-1)] = size
	pad = append(pad, size)

	return append(append([]byte{}, p.buffer...), pad...), nil
}

func (p *ISO10126) Unpad() ([]byte, error) {
	// check length
	length := len(p.buffer)
	if length%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	// Unpadding
	return p.buffer, nil
}

func (p *ISO10126) Name() string {
	return p.name
}
