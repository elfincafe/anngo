package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type CFB struct {
	name  string
	iv    []byte
	block cipher.Block
}

func NewCFB(iv []byte) *CFB {
	m := new(CFB)
	m.name = "CFB"
	copy(m.iv, Resize(iv, aes.BlockSize))
	return m
}

func (m *CFB) setBlock(block cipher.Block) {
	m.block = block
}

func (m *CFB) encrypt(b []byte) ([]byte, error) {
	stream := cipher.NewCFBEncrypter(m.block, m.iv)
	cipherText := make([]byte, len(b))
	stream.XORKeyStream(cipherText, b)
	return cipherText, nil
}

func (m *CFB) decrypt(b []byte) ([]byte, error) {
	stream := cipher.NewCFBDecrypter(m.block, m.iv)
	plainText := make([]byte, len(b))
	stream.XORKeyStream(plainText, b)
	return plainText, nil
}

func (m *CFB) Name() string {
	return m.name
}
