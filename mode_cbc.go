package anngo

import "crypto/rand"

func NewCBC(key []byte, p PaddingInterface) *CBC {
	aes := new(CBC)
	aes.key = make([]byte, len(key))
	copy(aes.key, key)
	aes.p = p
	aes.iv = make([]byte, BlockSize)
	rand.Read(aes.iv)
	return aes
}

func (aes *CBC) Encrypt(s []byte) ([]byte, error) {
	var err error
	d := []byte{}
	return d, err
}

func (aes *CBC) Decrypt(s []byte) ([]byte, error) {
	var err error
	d := []byte{}
	return d, err
}

func (aes *CBC) IV() []byte {
	return aes.iv
}

func (aes *CBC) SetIV(iv []byte) error {
	return copyIV(aes.iv, iv)
}
