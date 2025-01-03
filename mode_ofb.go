package anngo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func NewOFB(key []byte) *OFB {
	m := new(OFB)
	m.key = make([]byte, len(key))
	copy(m.key, key)
	m.iv = make([]byte, BlockSize)
	rand.Read(m.iv)
	return m
}

func (m *OFB) createBlock() error {
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

func (m *OFB) Encrypt(src []byte) ([]byte, error) {
	// Block
	err := m.createBlock()
	if err != nil {
		return nil, err
	}
	// BlockMode
	dst := make([]byte, len(src))
	stream := cipher.NewOFB(m.block, m.iv)
	stream.XORKeyStream(dst, src)
	return dst, nil
}

func (m *OFB) Decrypt(src []byte) ([]byte, error) {
	// Block
	err := m.createBlock()
	if err != nil {
		return nil, err
	}
	// BlockMode
	dst := make([]byte, len(src))
	stream := cipher.NewOFB(m.block, m.iv)
	stream.XORKeyStream(dst, src)
	return dst, nil
}

func (m *OFB) IV() []byte {
	return m.iv
}

func (m *OFB) SetIV(iv []byte) error {
	return copyIV(m.iv, iv)
}
