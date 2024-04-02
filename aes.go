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

func newAes(key []byte, blockSize int) *AES {
	aes := new(AES)
	aes.blockSize = blockSize
	aes.key = key
	return aes
}

func NewAes128(key []byte) *AES {
	aes := newAes(key, BlockSize128)
	return aes
}

func NewAes192(key []byte) *AES {
	aes := newAes(key, BlockSize192)
	return aes
}

func NewAes256(key []byte) *AES {
	aes := newAes(key, BlockSize256)
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

func Resize(value []byte, blockSize int) []byte {
	blockByte := blockSize / 8
	buf := make([]byte, blockByte)
	for k, v := range value {
		idx := k % blockByte
		buf[idx] ^= v
	}
	// for _, v := range buf {
	// 	fmt.Printf("0x%02x, ", v)
	// }
	// println("")
	return buf
}
