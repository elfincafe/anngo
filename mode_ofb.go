package anngo

func NewOFB(key, iv []byte) *OFB {
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
