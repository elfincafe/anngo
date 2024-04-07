package anngo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

const (
	KeySize16 = 16
	KeySize24 = 24
	KeySize32 = 32
)

type (
	Mode interface {
		setBlock(cipher.Block)
		encrypt([]byte) ([]byte, error)
		decrypt([]byte) ([]byte, error)
		Name() string
	}
	Padding interface {
		Pad([]byte) ([]byte, error)
		Unpad([]byte) ([]byte, error)
		Name() string
	}
	AES struct {
		mode    *Mode
		padding *Padding
	}
)

func Generate(size int) []byte {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return []byte{}
	}
	return b
}

func Resize(value []byte, size int) []byte {
	if size < 0 {
		return value
	}
	buf := make([]byte, size)
	for k, v := range value {
		idx := k % size
		buf[idx] ^= v
	}
	return buf
}

func NewAes(key []byte, mode *Mode, padding *Padding) (*AES, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aes := new(AES)
	aes.mode = mode
	(*aes.mode).setBlock(block)
	aes.padding = padding
	return aes, nil
}

func (aes *AES) Encrypt(b []byte) ([]byte, error) {
	return (*aes.mode).encrypt(b)
}

func (aes *AES) Decrypt(b []byte) ([]byte, error) {
	return (*aes.mode).decrypt(b)
}
