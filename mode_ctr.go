package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type (
	CTR struct {
		name  string
		block cipher.Block
		iv    []byte
	}
)

func NewAesCtr(key, iv []byte) (*AES, error) {
	var err error
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := CTR{
		name:  "CTR",
		block: block,
		iv:    make([]byte, aes.BlockSize),
	}
	copy(mode.iv, Resize(iv, aes.BlockSize))
	aes := newAes(block, mode)
	return aes, nil
}

func (m CTR) Name() string {
	return m.name
}

func (m CTR) encrypt(v []byte) ([]byte, error) {
	stream := cipher.NewCTR(m.block, m.iv)
	cipherText := make([]byte, len(v))
	stream.XORKeyStream(cipherText, v)
	return cipherText, nil
}

func (m CTR) decrypt(v []byte) ([]byte, error) {
	return m.encrypt(v)
}
