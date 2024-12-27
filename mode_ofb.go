package anngo

func NewOFB(key []byte, p PaddingInterface) *OFB {
	m := new(OFB)
	return m
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
