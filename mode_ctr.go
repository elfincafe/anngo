package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type (
	CTR struct {
		name string
		iv   []byte
	}
)

func NewCTR(iv []byte) CTR {
	m := CTR{
		name: "CTR",
		iv:   make([]byte, aes.BlockSize),
	}
	copy(m.iv, Resize(iv, aes.BlockSize))
	return m
}

func (m CTR) Name() string {
	return m.name
}

func (m CTR) encrypt(block cipher.Block, v []byte) ([]byte, error) {
	stream := cipher.NewCTR(block, m.iv)
	cipherText := make([]byte, len(v))
	stream.XORKeyStream(cipherText, v)
	return cipherText, nil
}

func (m CTR) decrypt(block cipher.Block, v []byte) ([]byte, error) {
	return m.encrypt(block, v)
}
