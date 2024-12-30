package anngo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func NewCFB(key []byte) *CFB {
	m := new(CFB)
	m.key = make([]byte, len(key))
	copy(m.key, key)
	m.iv = make([]byte, BlockSize)
	rand.Read(m.iv)
	return m
}

func (m *CFB) createBlock() error {
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

func (m *CFB) Encrypt(src []byte) ([]byte, error) {
	// Block
	err := m.createBlock()
	if err != nil {
		return nil, err
	}
	// BlockMode
	dst := make([]byte, len(src))
	steam := cipher.NewCFBEncrypter(m.block, m.iv)
	steam.XORKeyStream(dst, src)
	return dst, nil
}

func (m *CFB) Decrypt(src []byte) ([]byte, error) {
	// Block
	err := m.createBlock()
	if err != nil {
		return nil, err
	}
	// BlockMode
	dst := make([]byte, len(src))
	steam := cipher.NewCFBEncrypter(m.block, m.iv)
	steam.XORKeyStream(dst, src)
	return dst, nil
}

func (m *CFB) IV() []byte {
	return m.iv
}

func (m *CFB) SetIV(iv []byte) error {
	return copyIV(m.iv, iv)
}
