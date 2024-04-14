package anngo

import (
	"crypto/cipher"
	"crypto/rand"
)

const (
	paddingNone     = 0
	paddingPKCS7    = 1
	paddingZERO     = 2
	paddingANSIX923 = 3
	paddingISO10126 = 4
	modeEBC         = 1
	modeCBC         = 2
	modeCFB         = 3
	modeOFB         = 4
	modeCTR         = 5
)

type (
	Padding interface {
		Name() string
		Pad([]byte) ([]byte, error)
		Unpad([]byte) ([]byte, error)
	}
	Mode interface {
		Name() string
		encrypt([]byte) ([]byte, error)
		decrypt([]byte) ([]byte, error)
	}
	AES struct {
		block   cipher.Block
		mode    Mode
		padding Padding
	}
)

func Generate(size int) []byte {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return []byte{}
	}
	return b
}

func Resize(value []byte, size int) []byte {
	if size < 0 {
		return value
	}
	buf := make([]byte, size)
	for k, v := range value {
		idx := k % size
		buf[idx] ^= v
	}
	return buf
}

func newAes(block cipher.Block, mode Mode) *AES {
	a := new(AES)
	a.block = block
	a.mode = mode
	a.padding = nil
	return a
}

func (a *AES) Padding(padding Padding) {
	a.padding = padding
}

func (a *AES) Encrypt(v []byte) ([]byte, error) {
	var err error
	var paddedText []byte

	if a.padding != nil {
		paddedText, err = a.padding.Pad(v)
		if err != nil {
			return nil, err
		}
	} else {
		paddedText = v
	}
	return a.mode.encrypt(paddedText)
}

func (a *AES) Decrypt(v []byte) ([]byte, error) {
	plainText, err := a.mode.decrypt(v)
	if err != nil {
		return nil, err
	}
	if a.padding != nil {
		return a.padding.Unpad(plainText)
	}
	return plainText, nil
}
