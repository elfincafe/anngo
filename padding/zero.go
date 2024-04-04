package padding

import (
	"bytes"
	"crypto/aes"
	"errors"
)

type Zero struct {
	name   string
	buffer []byte
}

func NewZero(buffer []byte) *Zero {
	p := new(Zero)
	p.name = "Zero"
	p.buffer = make([]byte, len(buffer))
	copy(p.buffer, buffer)
	return p
}

func (p *Zero) Pad() ([]byte, error) {
	// check length
	length := len(p.buffer)
	if length%aes.BlockSize == 0 {
		return p.buffer, nil
	}
	// Padding
	size := aes.BlockSize - len(p.buffer)%aes.BlockSize
	pad := bytes.Repeat([]byte{0x00}, size)
	p.buffer = append(p.buffer, pad...)

	return p.buffer, nil
}

func (p *Zero) Unpad() ([]byte, error) {
	// check length
	length := len(p.buffer)
	if length%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	// Unpadding
	limit := length - aes.BlockSize + 1
	idx := limit + 1
	for i := length - 1; i > limit; i-- {
		if p.buffer[i] != 0x00 {
			idx = i + 1
			break
		}
	}

	return p.buffer[:idx], nil
}

func (p *Zero) Name() string {
	return p.name
}
