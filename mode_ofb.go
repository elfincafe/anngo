package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type (
	OFB struct {
		name string
		iv   []byte
	}
)

func NewOFB(iv []byte) OFB {
	m := OFB{
		name: "OFB",
		iv:   make([]byte, aes.BlockSize),
	}
	copy(m.iv, Resize(iv, aes.BlockSize))
	return m
}

func (m OFB) Name() string {
	return m.name
}

func (m OFB) encrypt(block cipher.Block, v []byte) ([]byte, error) {
	stream := cipher.NewOFB(block, m.iv)
	cipherText := make([]byte, len(v))
	stream.XORKeyStream(cipherText, v)
	return cipherText, nil
}

func (m OFB) decrypt(block cipher.Block, v []byte) ([]byte, error) {
	return m.encrypt(block, v)
}
