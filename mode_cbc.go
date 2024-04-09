package anngo

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

type CBC struct {
	Mode
}

func NewCBC(iv []byte) CBC {
	m := CBC{
		Mode{
			name:    "CBC",
			iv:      make([]byte, aes.BlockSize),
			block:   nil,
			padding: nil,
		},
	}
	copy(m.iv, Resize(iv, aes.BlockSize))
	return m
}

func (m CBC) Name() string {
	return m.name
}

func (m CBC) setBlock(block cipher.Block) {
	m.block = block
}

func (m CBC) setPadding(padding IPadding) {
	m.padding = padding
	fmt.Println("setPadding: ", m.padding)
}

func (m CBC) encrypt(b []byte) ([]byte, error) {
	fmt.Println("encrypt: ", m.padding)
	paddedText, err := m.padding.Pad(b)
	if err != nil {
		return nil, err
	}
	cipherText := make([]byte, len(paddedText))
	enc := cipher.NewCBCEncrypter(m.block, m.iv)
	enc.CryptBlocks(cipherText, paddedText)

	return cipherText, nil
}

func (m CBC) decrypt(b []byte) ([]byte, error) {
	dec := cipher.NewCBCDecrypter(m.block, m.iv)
	var paddedText []byte
	dec.CryptBlocks(paddedText, b)
	plainText, err := m.padding.Unpad(paddedText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
