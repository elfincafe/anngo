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
	size := byte(aes.BlockSize - len(p.buffer)%aes.BlockSize)
	pad := bytes.Repeat([]byte{0x00}, int(size-1))
	pad = append(pad, size)
	p.buffer = append(p.buffer, pad...)

	return append(append([]byte{}, p.buffer...), pad...), nil
}

func (p *ANSIX923) Unpad() ([]byte, error) {
	// check length
	length := len(p.buffer)
	if length%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	// Unpadding
	return p.buffer, nil
}

func (p *ANSIX923) Name() string {
	return p.name
}
