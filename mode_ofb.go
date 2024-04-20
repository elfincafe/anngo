package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type (
	OFB struct {
		name  string
		block cipher.Block
		iv    []byte
	}
)

func NewAesOfb(key, iv []byte) (*AES, error) {
	var err error
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// mode := OFB{
	// 	name:  "OFB",
	// 	block: block,
	// 	iv:    make([]byte, aes.BlockSize),
	// }
	mode := new(OFB)
	mode.name = "OFB"
	mode.block = block
	mode.iv = make([]byte, aes.BlockSize)
	copy(mode.iv, Resize(iv, aes.BlockSize))
	aes := newAes(block, mode)
	return aes, nil
}

func (m *OFB) Name() string {
	return m.name
}

func (m *OFB) encrypt(v []byte) ([]byte, error) {
	stream := cipher.NewOFB(m.block, m.iv)
	cipherText := make([]byte, len(v))
	stream.XORKeyStream(cipherText, v)
	return cipherText, nil
}

func (m *OFB) decrypt(v []byte) ([]byte, error) {
	return m.encrypt(v)
}
