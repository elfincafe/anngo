package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type OFB struct {
	Mode
}

func NewOFB(iv []byte) OFB {
	m := OFB{
		Mode{
			name:    "OFB",
			iv:      make([]byte, aes.BlockSize),
			block:   nil,
			padding: nil,
		},
	}
	copy(m.iv, Resize(iv, aes.BlockSize))
	return m
}

func (m OFB) setBlock(block cipher.Block) {
	m.block = block
}

func (m OFB) setPadding(padding *IPadding) {
}

func (m OFB) encrypt(b []byte) ([]byte, error) {
	stream := cipher.NewOFB(m.block, m.iv)
	cipherText := make([]byte, len(b))
	stream.XORKeyStream(cipherText, b)
	return cipherText, nil
}

func (m OFB) decrypt(b []byte) ([]byte, error) {
	return m.encrypt(b)
}

func (m OFB) Name() string {
	return m.name
}
