package anngo

func NewECB(key []byte, p PaddingInterface) *ECB {
	aes := new(ECB)
	aes.key = make([]byte, len(key))
	copy(aes.key, key)
	return aes
}

func (aes *ECB) Encrypt(s []byte) ([]byte, error) {
	var err error
	d := []byte{}
	return d, err
}

func (aes *ECB) Decrypt(s []byte) ([]byte, error) {
	var err error
	d := []byte{}
	return d, err
}
