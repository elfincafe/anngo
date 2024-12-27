package anngo

func NewECB(key []byte, p PaddingInterface) *ECB {
	m := new(ECB)
	return m
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
