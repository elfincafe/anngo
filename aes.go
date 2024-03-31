package anngo

import (
	"crypto/rand"
	"fmt"

	"anngo/mode"
	"anngo/padding"
)

const (
	BlockSize128 = 128
	BlockSize192 = 192
	BlockSize256 = 256
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
	aes := newAes(password, BlockSize128)
	return aes
}

func NewAes192(password []byte) *AES {
	aes := newAes(password, BlockSize192)
	return aes
}

func NewAes256(password []byte) *AES {
	aes := newAes(password, BlockSize256)
	return aes
}

func (aes *AES) Encrypt(p *padding.Padding) ([]byte, error) {
	// Check Block Size
	if aes.blockSize != BlockSize128 && aes.blockSize != BlockSize192 && aes.blockSize != BlockSize256 {
		return nil, fmt.Errorf(`Invalid Block Size %d.`, aes.blockSize)
	}

	return []byte{}, nil
}

func (aes *AES) Decrypt(p *padding.Padding) ([]byte, error) {
	// Check Block Size
	if aes.blockSize != BlockSize128 && aes.blockSize != BlockSize192 && aes.blockSize != BlockSize256 {
		return nil, fmt.Errorf(`Invalid Block Size %d.`, aes.blockSize)
	}

	return []byte{}, nil
}

func Generate(blockSize int) []byte {
	b := make([]byte, blockSize)
	_, err := rand.Read(b)
	if err != nil {
		return []byte{}
	}
	return b
}
