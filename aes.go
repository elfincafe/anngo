package anngo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type (
	IPadding interface {
		Name() string
		Pad([]byte) ([]byte, error)
		Unpad([]byte) ([]byte, error)
	}
	IMode interface {
		Name() string
		encrypt([]byte) ([]byte, error)
		decrypt([]byte) ([]byte, error)
		setBlock(cipher.Block)
		setPadding(IPadding)
	}
	Mode struct {
		name    string
		iv      []byte
		block   cipher.Block
		padding *IPadding
	}
	AES struct {
		mode *IMode
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

func NewAes(key []byte, mode IMode, padding IPadding) (*AES, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode.setBlock(block)
	mode.setPadding(padding)
	aes := new(AES)
	aes.mode = mode
	fmt.Println(mode)
	return aes, nil
}

func (aes *AES) Encrypt(b []byte) ([]byte, error) {
	b, err := aes.mode.encrypt(b)
	return b, err
}

func (aes *AES) Decrypt(b []byte) ([]byte, error) {
	return aes.mode.decrypt(b)
}
