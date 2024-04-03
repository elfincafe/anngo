package anngo

import (
	"crypto/rand"

	"anngo/mode"
	"anngo/padding"
)

const (
	KeyLength128 = 128
	KeyLength192 = 192
	KeyLength256 = 256
)

type AES struct {
	buffer    []byte
	key       []byte
	keyLength int
	mode      *mode.Mode
}

func newAes(key []byte, keyLength int, mode *mode.Mode) *AES {
	aes := new(AES)
	aes.keyLength = keyLength
	aes.key = key
	aes.mode = mode
	return aes
}

func NewAes128(key []byte, mode *mode.Mode) *AES {
	aes := newAes(key, KeyLength128, mode)
	return aes
}

func NewAes192(key []byte, mode *mode.Mode) *AES {
	aes := newAes(key, KeyLength192, mode)
	return aes
}

func NewAes256(key []byte, mode *mode.Mode) *AES {
	aes := newAes(key, KeyLength256, mode)
	return aes
}

func (aes *AES) Encrypt(p *padding.Padding) ([]byte, error) {

	return []byte{}, nil
}

func (aes *AES) Decrypt(p *padding.Padding) ([]byte, error) {

	return []byte{}, nil
}

func Generate(size int) []byte {
	b := make([]byte, size)
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
