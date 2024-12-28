package anngo

import "crypto/rand"

func NewCFB(key []byte) *CFB {
	aes := new(CFB)
	aes.key = make([]byte, len(key))
	copy(aes.key, key)
	aes.iv = make([]byte, BlockSize)
	rand.Read(aes.iv)
	return aes
}

func (aes *CFB) Encrypt(s []byte) ([]byte, error) {
	var err error
	d := []byte{}
	return d, err
}

func (aes *CFB) Decrypt(s []byte) ([]byte, error) {
	var err error
	d := []byte{}
	return d, err
}

func (aes *CFB) IV() []byte {
	return aes.iv
}

func (aes *CFB) SetIV(iv []byte) error {
	return copyIV(aes.iv, iv)
}
