package anngo

import (
	"bytes"
	"crypto/aes"
	"errors"
)

type ANSIX923 struct {
	name string
}

func NewANSIX923() ANSIX923 {
	p := ANSIX923{
		name: "ANSI X9.23",
	}
	return p
}

func (p ANSIX923) Name() string {
	return p.name
}

func (p ANSIX923) Pad(b []byte) ([]byte, error) {
	// check length
	length := len(b)
	if length%aes.BlockSize == 0 {
		return b, nil
	}
	// Padding
	size := byte(aes.BlockSize - length%aes.BlockSize)
	buffer := make([]byte, length+int(size))
	copy(buffer, b)
	buffer[length-1] = size

	return buffer, nil
}

func (p ANSIX923) Unpad(b []byte) ([]byte, error) {
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
	pattern := make([]byte, int(lastByte))
	s := length - len(pattern)
	if !bytes.Equal(b[s:], pattern) {
		return nil, errors.New("ciphertext is not a invalid padding")
	}

	return b[:s], nil
}
