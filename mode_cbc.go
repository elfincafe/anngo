package anngo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func NewCBC(key []byte, p PaddingInterface) *CBC {
	m := new(CBC)
	m.key = make([]byte, len(key))
	copy(m.key, key)
	m.p = p
	m.iv = make([]byte, BlockSize)
	rand.Read(m.iv)
	return m
}

func (m *CBC) createBlock() error {
	if m.block != nil {
		return nil
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return err
	}
	m.block = block

	return nil
}

func (m *CBC) Encrypt(s []byte) ([]byte, error) {
	// Block
	err := m.createBlock()
	if err != nil {
		return nil, err
	}
	// BlockMode
	blockMode := cipher.NewCBCEncrypter(m.block, m.iv)
	text := m.p.Pad(s)
	d := make([]byte, len(text))
	blockMode.CryptBlocks(d, text)

	return d, nil
}

func (m *CBC) Decrypt(s []byte) ([]byte, error) {
	// Block
	err := m.createBlock()
	if err != nil {
		return nil, err
	}
	// BlockMode
	blockMode := cipher.NewCBCDecrypter(m.block, m.iv)
	d := make([]byte, len(s))
	blockMode.CryptBlocks(d, s)
	text := m.p.Unpad(d)

	return text, nil
}

func (m *CBC) IV() []byte {
	return m.iv
}

func (m *CBC) SetIV(iv []byte) error {
	return copyIV(m.iv, iv)
}
