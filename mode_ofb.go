package anngo

import "crypto/rand"

func NewOFB(key []byte) *OFB {
	aes := new(OFB)
	aes.key = make([]byte, len(key))
	copy(aes.key, key)
	aes.iv = make([]byte, BlockSize)
	rand.Read(aes.iv)
	return aes
}

func (aes *OFB) Encrypt(s []byte) ([]byte, error) {
	var err error
	d := []byte{}
	return d, err
}

func (aes *OFB) Decrypt(s []byte) ([]byte, error) {
	var err error
	d := []byte{}
	return d, err
}

func (aes *OFB) IV() []byte {
	return aes.iv
}

func (aes *OFB) SetIV(iv []byte) error {
	return copyIV(aes.iv, iv)
}
