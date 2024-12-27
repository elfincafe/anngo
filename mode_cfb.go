package anngo

func NewCFB(key []byte, p PaddingInterface) *CFB {
	m := new(CFB)
	return m
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
