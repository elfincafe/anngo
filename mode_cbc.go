package anngo

import (
	"crypto/cipher"
)

type CBC struct {
	name    string
	iv      []byte
	block   cipher.Block
	padding *Padding
}

func NewCBC(iv []byte) *CBC {
	m := new(CBC)
	m.name = "CBC"
	copy(m.iv, Resize(iv, 128))
	return m
}

func (m *CBC) setBlock(block cipher.Block) {
	m.block = block
}

func (m *CBC) encrypt(b []byte) ([]byte, error) {
	paddedText, err := (*m.padding).Pad(b)
	if err != nil {
		return nil, err
	}
	cipherText := make([]byte, len(paddedText))
	enc := cipher.NewCBCEncrypter(m.block, m.iv)
	enc.CryptBlocks(cipherText, paddedText)

	return cipherText, nil
}

func (m *CBC) decrypt(b []byte) ([]byte, error) {
	dec := cipher.NewCBCDecrypter(m.block, m.iv)
	var paddedText []byte
	dec.CryptBlocks(paddedText, b)
	plainText, err := (*m.padding).Unpad(paddedText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func (m *CBC) Name() string {
	return m.name
}
