package anngo

import (
	"crypto/rand"

	"anngo/mode"
	"anngo/padding"
)

const (
	AES128 = 128
	AES192 = 192
	AES256 = 256
)

type AES struct {
	blockSize int
	buffer    []byte
	key       []byte
	mode      *mode.Mode
}

func newAes(password []byte, blockSize int) *AES {
	aes := new(AES)
	aes.blockSize = blockSize
	return aes
}

func NewAes128(password []byte) *AES {
	aes := newAes(password, AES128)
	return aes
}

func NewAes192(password []byte) *AES {
	aes := newAes(password, AES192)
	return aes
}

func NewAes256(password []byte) *AES {
	aes := newAes(password, AES256)
	return aes
}

func (aes *AES) Encrypt(p *padding.Padding) []byte {
	return []byte{}
}

func (aes *AES) Decrypt(p *padding.Padding) []byte {
	return []byte{}
}

func Generate(blockSize int) []byte {
	b := make([]byte, blockSize, blockSize)
	_, err := rand.Read(b)
	if err != nil {
		return []byte{}
	}
	return b
}
