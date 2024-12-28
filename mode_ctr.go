package anngo

import "crypto/rand"

func NewCTR(key []byte) *CTR {
	aes := new(CTR)
	aes.key = make([]byte, len(key))
	copy(aes.key, key)
	aes.iv = make([]byte, BlockSize)
	rand.Read(aes.iv)
	return aes
}

func (aes *CTR) Encrypt(s []byte) ([]byte, error) {
	var err error
	d := []byte{}
	return d, err
}

func (aes *CTR) Decrypt(s []byte) ([]byte, error) {
	var err error
	d := []byte{}
	return d, err
}

func (aes *CTR) IV() []byte {
	return aes.iv
}

func (aes *CTR) SetIV(iv []byte) error {
	return copyIV(aes.iv, iv)
}
