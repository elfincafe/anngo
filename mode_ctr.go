package anngo

import (
	"crypto/aes"
	"crypto/cipher"
)

type CTR struct {
	Mode
}

func NewCTR(iv []byte) CTR {
	m := CTR{
		Mode{
			name:    "CTR",
			iv:      make([]byte, aes.BlockSize),
			block:   nil,
			padding: nil,
		},
	}
	copy(m.iv, Resize(iv, aes.BlockSize))
	return m
}

func (m CTR) Name() string {
	return m.name
}

func (m CTR) setBlock(block cipher.Block) {
	m.block = block
}

func (m CTR) setPadding(padding *IPadding) {
}

func (m CTR) encrypt(b []byte) ([]byte, error) {
	stream := cipher.NewCTR(m.block, m.iv)
	cipherText := make([]byte, len(b))
	stream.XORKeyStream(cipherText, b)
	return cipherText, nil
}

func (m CTR) decrypt(b []byte) ([]byte, error) {
	return m.encrypt(b)
}
