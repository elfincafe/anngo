package anngo

func NewCBC(key []byte, p PaddingInterface) *CBC {
	m := new(CBC)
	return m
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
