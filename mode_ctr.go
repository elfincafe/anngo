package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type CTR struct {
	name  string
	iv    []byte
	block cipher.Block
}

func NewCTR(iv []byte) *CTR {
	m := new(CTR)
	m.name = "CTR"
	copy(m.iv, Resize(iv, aes.BlockSize))
	return m
}

func (m *CTR) setBlock(block cipher.Block) {
	m.block = block
}

func (m *CTR) encrypt(b []byte) ([]byte, error) {
	stream := cipher.NewCTR(m.block, m.iv)
	cipherText := make([]byte, len(b))
	stream.XORKeyStream(cipherText, b)
	return cipherText, nil
}

func (m *CTR) decrypt(b []byte) ([]byte, error) {
	return m.encrypt(b)
}

func (m *CTR) Name() string {
	return m.name
}
