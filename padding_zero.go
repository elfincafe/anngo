package anngo

import (
	"crypto/aes"
	"errors"
)

type ZERO struct {
	name string
}

func NewZero() *ZERO {
	// p := ZERO{
	// 	name: "ZERO",
	// }
	p := new(ZERO)
	p.name = "ZERO"
	return p
}

func (p *ZERO) Name() string {
	return p.name
}

func (p *ZERO) Pad(b []byte) ([]byte, error) {
	// check length
	length := len(b)
	if length%aes.BlockSize == 0 {
		return b, nil
	}
	// Padding
	size := byte(aes.BlockSize - length%aes.BlockSize)
	buffer := make([]byte, length+int(size))
	copy(buffer, b)

	return buffer, nil
}

func (p *ZERO) Unpad(b []byte) ([]byte, error) {
	// check length
	length := len(b)
	if length%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	// Unpadding
	limit := length - aes.BlockSize
	idx := limit + 1
	for i := length - 1; i > limit; i-- {
		if b[i] != 0x00 {
			idx = i + 1
			break
		}
	}

	return b[:idx], nil
}
