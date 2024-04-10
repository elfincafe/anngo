package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type (
	CBC struct {
		name string
		iv   []byte
	}
)

func NewCBC(iv []byte) CBC {
	m := CBC{
		name: "CBC",
		iv:   make([]byte, aes.BlockSize),
	}
	copy(m.iv, Resize(iv, aes.BlockSize))
	return m
}

func (m CBC) Name() string {
	return m.name
}

func (m CBC) encrypt(block cipher.Block, v []byte) ([]byte, error) {
	cipherText := make([]byte, len(v))
	cipher.NewCBCEncrypter(block, m.iv).CryptBlocks(cipherText, v)
	return cipherText, nil
}

func (m CBC) decrypt(block cipher.Block, v []byte) ([]byte, error) {
	plainText := make([]byte, len(v))
	cipher.NewCBCDecrypter(block, m.iv).CryptBlocks(plainText, v)
	return plainText, nil
}
