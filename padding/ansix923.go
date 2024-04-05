package padding

import (
	"bytes"
	"crypto/aes"
	"errors"
)

type ANSIX923 struct {
	name   string
	buffer []byte
}

func NewAnsiX923(buffer []byte) *ANSIX923 {
	p := new(ANSIX923)
	p.name = "ANSI X9.23"
	p.buffer = make([]byte, len(buffer))
	copy(p.buffer, buffer)
	return p
}

func (p *ANSIX923) Pad() ([]byte, error) {
	// check length
	length := len(p.buffer)
	if length%aes.BlockSize == 0 {
		return p.buffer, nil
	}
	// Padding
	size := byte(aes.BlockSize - length%aes.BlockSize)
	pad := bytes.Repeat([]byte{0x00}, int(size-1))
	pad = append(pad, size)
	p.buffer = append(p.buffer, pad...)

	return p.buffer, nil
}

func (p *ANSIX923) Unpad() ([]byte, error) {
	// check length
	length := len(p.buffer)
	if length%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	// Unpadding
	b := p.buffer[len(p.buffer)-1]
	if b > 0x0f {
		return p.buffer, nil
	}
	pattern := append(bytes.Repeat([]byte{0x00}, int(b-1)), b)
	s := length - int(b)
	if !bytes.Equal(p.buffer[s:], pattern) {
		return nil, errors.New("ciphertext is not a invalid padding")
	}

	return p.buffer[:s], nil
}

func (p *ANSIX923) Name() string {
	return p.name
}
