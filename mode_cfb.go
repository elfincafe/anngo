package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type CFB struct {
	Mode
}

func NewCFB(iv []byte) CFB {
	m := CFB{
		Mode{
			name:    "CFB",
			iv:      make([]byte, aes.BlockSize),
			block:   nil,
			padding: nil,
		},
	}
	copy(m.iv, Resize(iv, aes.BlockSize))
	return m
}

func (m CFB) Name() string {
	return m.name
}

func (m CFB) setBlock(block cipher.Block) {
	m.block = block
}

func (m CFB) setPadding(padding *IPadding) {
}

func (m CFB) encrypt(b []byte) ([]byte, error) {
	stream := cipher.NewCFBEncrypter(m.block, m.iv)
	cipherText := make([]byte, len(b))
	stream.XORKeyStream(cipherText, b)
	return cipherText, nil
}

func (m CFB) decrypt(b []byte) ([]byte, error) {
	stream := cipher.NewCFBDecrypter(m.block, m.iv)
	plainText := make([]byte, len(b))
	stream.XORKeyStream(plainText, b)
	return plainText, nil
}
