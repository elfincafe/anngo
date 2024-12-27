package anngo

func NewCTR(key []byte) *CTR {
	m := new(CTR)
	return m
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
