package padding

import (
	"bytes"
	"crypto/aes"
	"errors"
	"fmt"
)

type PKCS7 struct {
	name   string
	buffer []byte
}

func NewPkcs7(buffer []byte) *PKCS7 {
	p := new(PKCS7)
	p.name = "PKCS7"
	p.buffer = make([]byte, len(buffer))
	copy(p.buffer, buffer)
	return p
}

func (p *PKCS7) Pad() ([]byte, error) {
	// check length
	length := len(p.buffer)
	if length%aes.BlockSize == 0 {
		return p.buffer, nil
	}
	// Padding
	size := byte(aes.BlockSize - len(p.buffer)%aes.BlockSize)
	pad := bytes.Repeat([]byte{size}, int(size))
	p.buffer = append(p.buffer, pad...)

	return p.buffer, nil
}

func (p *PKCS7) Unpad() ([]byte, error) {
	// check length
	length := len(p.buffer)
	if length%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	// Unpadding
	b := p.buffer[len(p.buffer)-1]
	if b < 0x00 || b > 0x0f {
		return p.buffer, nil
	}
	pattern := bytes.Repeat([]byte{b}, int(b))
	s := length - int(b)
	fmt.Println(p.buffer[s:])
	if !bytes.Equal(p.buffer[s:], pattern) {
		return nil, errors.New("ciphertext is not a invalid padding")
	}

	return p.buffer[:s], nil
}

func (p *PKCS7) Name() string {
	return p.name
}
