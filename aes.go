package anngo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

type (
	Padding interface {
		Name() string
		Pad([]byte) ([]byte, error)
		Unpad([]byte) ([]byte, error)
	}
	Mode interface {
		encrypt(cipher.Block, []byte) ([]byte, error)
		decrypt(cipher.Block, []byte) ([]byte, error)
	}
	AES struct {
		block   cipher.Block
		mode    Mode
		padding Padding
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

func NewAes(key []byte, mode Mode, padding Padding) (*AES, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a := new(AES)
	a.block = block
	a.mode = mode
	if padding != nil {
		a.padding = padding
	} else {
		a.padding = newNone()
	}
	return a, nil
}

func (a AES) Encrypt(v []byte) ([]byte, error) {
	paddedText, err := a.padding.Pad(v)
	if err != nil {
		return nil, err
	}
	return a.mode.encrypt(a.block, paddedText)
}

func (a AES) Decrypt(v []byte) ([]byte, error) {
	plainText, err := a.mode.decrypt(a.block, v)
	if err != nil {
		return nil, err
	}
	return a.padding.Unpad(plainText)
}
