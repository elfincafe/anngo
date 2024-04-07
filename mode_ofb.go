package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type OFB struct {
	name  string
	iv    []byte
	block cipher.Block
}

func NewOFB(iv []byte) *OFB {
	m := new(OFB)
	m.name = "OFB"
	copy(m.iv, Resize(iv, aes.BlockSize))
	return m
}

func (m *OFB) setBlock(block cipher.Block) {
	m.block = block
}

func (m *OFB) encrypt(b []byte) ([]byte, error) {
	stream := cipher.NewOFB(m.block, m.iv)
	cipherText := make([]byte, len(b))
	stream.XORKeyStream(cipherText, b)
	return cipherText, nil
}

func (m *OFB) decrypt(b []byte) ([]byte, error) {
	return m.encrypt(b)
}

func (m *OFB) Name() string {
	return m.name
}
