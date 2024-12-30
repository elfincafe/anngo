package anngo

import (
	"crypto/aes"
)

func NewECB(key []byte, p PaddingInterface) *ECB {
	m := new(ECB)
	m.key = make([]byte, len(key))
	copy(m.key, key)
	return m
}

func (m *ECB) createBlock() error {
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

func (m *ECB) Encrypt(s []byte) ([]byte, error) {
	// Block
	err := m.createBlock()
	if err != nil {
		return nil, err
	}
	src := m.p.Pad(s)
	length := len(src)
	dst := make([]byte, length)
	for i := 0; i*BlockSize <= length; i++ {
		idx := i + BlockSize
		m.block.Encrypt(dst[idx:idx+BlockSize], src[idx:idx+BlockSize])
	}

	return dst, err
}

func (m *ECB) Decrypt(src []byte) ([]byte, error) {
	// Block
	err := m.createBlock()
	if err != nil {
		return nil, err
	}
	length := len(src)
	dst := make([]byte, length)
	for i := 0; i*BlockSize <= length; i++ {
		idx := i + BlockSize
		m.block.Encrypt(dst[idx:idx+BlockSize], src[idx:idx+BlockSize])
	}
	d := m.p.Unpad(dst)
	return d, err
}
