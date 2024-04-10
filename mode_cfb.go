package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type (
	CFB struct {
		name string
		iv   []byte
	}
)

func NewCFB(iv []byte) CFB {
	m := CFB{
		name: "CFB",
		iv:   make([]byte, aes.BlockSize),
	}
	copy(m.iv, Resize(iv, aes.BlockSize))
	return m
}

func (m CFB) Name() string {
	return m.name
}

func (m CFB) encrypt(block cipher.Block, v []byte) ([]byte, error) {
	stream := cipher.NewCFBEncrypter(block, m.iv)
	cipherText := make([]byte, len(v))
	stream.XORKeyStream(cipherText, v)
	return cipherText, nil
}

func (m CFB) decrypt(block cipher.Block, v []byte) ([]byte, error) {
	stream := cipher.NewCFBDecrypter(block, m.iv)
	plainText := make([]byte, len(v))
	stream.XORKeyStream(plainText, v)
	return plainText, nil
}
