package anngo

import (
	"crypto/aes"
	"crypto/rand"
)

const (
	BlockSize int = aes.BlockSize
	AES128        = 16
	AES192        = 24
	AES256        = 32
)

type (
	PaddingInterface interface {
		Pad([]byte) []byte
		Unpad([]byte) []byte
	}
	ModeInterface interface {
		Encrypt([]byte) ([]byte, error)
		Decrypt([]byte) ([]byte, error)
	}
	ZERO struct {
	}
	PKCS7 struct {
	}
	ANSIX923 struct {
	}
	ISO10126 struct {
	}
	ECB struct {
		key []byte
		p   PaddingInterface
	}
	CBC struct {
		key []byte
		p   PaddingInterface
		iv  []byte
	}
	CFB struct {
		key []byte
		iv  []byte
	}
	OFB struct {
		key []byte
		iv  []byte
	}
	CTR struct {
		key []byte
		iv  []byte
	}
)

func GenerateIV(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}
