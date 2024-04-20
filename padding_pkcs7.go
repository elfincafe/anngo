package anngo

import (
	"bytes"
	"crypto/aes"
	"errors"
	"fmt"
)

type PKCS7 struct {
	name string
}

func NewPkcs7() *PKCS7 {
	// p := PKCS7{
	// 	name: "PKCS7",
	// }
	p := new(PKCS7)
	p.name = "PKCS7"
	return p
}

func (p *PKCS7) Name() string {
	return p.name
}

func (p *PKCS7) Pad(b []byte) ([]byte, error) {
	fmt.Println("padding1")
	// check length
	length := len(b)
	if length%aes.BlockSize == 0 {
		return b, nil
	}
	// Padding
	size := byte(aes.BlockSize - length%aes.BlockSize)
	buffer := make([]byte, length+int(size))
	copy(buffer, b)
	copy(buffer[length:], bytes.Repeat([]byte{size}, int(size)))
	return buffer, nil
}

func (p *PKCS7) Unpad(b []byte) ([]byte, error) {
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
	pattern := bytes.Repeat([]byte{lastByte}, int(lastByte))
	s := length - len(pattern)
	if !bytes.Equal(b[s:], pattern) {
		return nil, errors.New("ciphertext is not a invalid padding")
	}

	return b[:s], nil
}
