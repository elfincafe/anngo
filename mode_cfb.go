package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type (
	CFB struct {
		name  string
		block cipher.Block
		iv    []byte
	}
)

func NewAesCfb(key, iv []byte) (*AES, error) {
	var err error
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := CFB{
		name:  "CFB",
		block: block,
		iv:    make([]byte, aes.BlockSize),
	}
	copy(mode.iv, Resize(iv, aes.BlockSize))
	aes := newAes(block, mode)
	return aes, nil
}

func (m CFB) Name() string {
	return m.name
}

func (m CFB) encrypt(v []byte) ([]byte, error) {
	stream := cipher.NewCFBEncrypter(m.block, m.iv)
	cipherText := make([]byte, len(v))
	stream.XORKeyStream(cipherText, v)
	return cipherText, nil
}

func (m CFB) decrypt(v []byte) ([]byte, error) {
	stream := cipher.NewCFBDecrypter(m.block, m.iv)
	plainText := make([]byte, len(v))
	stream.XORKeyStream(plainText, v)
	return plainText, nil
}
