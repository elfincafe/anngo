package anngo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
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
		key   []byte
		block cipher.Block
		p     PaddingInterface
	}
	CBC struct {
		key   []byte
		block cipher.Block
		p     PaddingInterface
		iv    []byte
	}
	CFB struct {
		key   []byte
		block cipher.Block
		iv    []byte
	}
	OFB struct {
		key   []byte
		block cipher.Block
		iv    []byte
	}
	CTR struct {
		key   []byte
		block cipher.Block
		iv    []byte
	}
)

func GenerateIV(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

func copyIV(d, s []byte) error {
	length := len(s)
	if len(d) < length {
		return fmt.Errorf("destination is less than source")
	}
	if length == BlockSize {
		copy(d, s)
		return nil
	} else {
		return fmt.Errorf("IV size must be %d bytes", BlockSize)
	}
}
