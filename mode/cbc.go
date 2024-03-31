package mode

type CBC struct {
	name string
	iv   []byte
}

func NewCBC(iv []byte) *CBC {
	m := new(CBC)
	m.name = "CBC"
	copy(m.iv, iv)
	return m
}

func (m *CBC) IV() []byte {
	return m.iv
}

func (m *CBC) Encrypt() ([]byte, error) {
	return nil, nil
}

func (m *CBC) Decrypt() ([]byte, error) {
	return nil, nil
}

func (m *CBC) Name() string {
	return m.name
}
