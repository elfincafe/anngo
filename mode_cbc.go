package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type (
	CBC struct {
		name  string
		block cipher.Block
		iv    []byte
	}
)

func NewAesCbc(key, iv []byte) (*AES, error) {
	var err error
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := CBC{
		name:  "CBC",
		block: block,
		iv:    make([]byte, aes.BlockSize),
	}
	copy(mode.iv, Resize(iv, aes.BlockSize))
	aes := newAes(block, mode)
	aes.Padding(NewPKCS7())
	return aes, nil
}

func (m CBC) Name() string {
	return m.name
}

func (m CBC) encrypt(v []byte) ([]byte, error) {
	cipherText := make([]byte, len(v))
	cipher.NewCBCEncrypter(m.block, m.iv).CryptBlocks(cipherText, v)
	return cipherText, nil
}

func (m CBC) decrypt(v []byte) ([]byte, error) {
	plainText := make([]byte, len(v))
	cipher.NewCBCDecrypter(m.block, m.iv).CryptBlocks(plainText, v)
	return plainText, nil
}
