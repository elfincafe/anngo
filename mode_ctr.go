package anngo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func NewCTR(key []byte) *CTR {
	m := new(CTR)
	m.key = make([]byte, len(key))
	copy(m.key, key)
	m.iv = make([]byte, BlockSize)
	rand.Read(m.iv)
	return m
}

func (m *CTR) createBlock() error {
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

func (m *CTR) Encrypt(src []byte) ([]byte, error) {
	// Block
	err := m.createBlock()
	if err != nil {
		return nil, err
	}
	// BlockMode
	dst := make([]byte, len(src))
	stream := cipher.NewCTR(m.block, m.iv)
	stream.XORKeyStream(dst, src)
	return dst, nil
}

func (m *CTR) Decrypt(src []byte) ([]byte, error) {
	return m.Encrypt(src)
}

func (m *CTR) IV() []byte {
	return m.iv
}

func (m *CTR) SetIV(iv []byte) error {
	return copyIV(m.iv, iv)
}
