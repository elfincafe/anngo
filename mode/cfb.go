package mode

import "anngo/padding"

type CFB struct {
	name string
	iv   []byte
}

func NewCFB(iv []byte) *CBC {
	m := new(CBC)
	m.name = "CFB"
	copy(m.iv, iv)
	return m
}

func (m *CFB) IV() []byte {
	return m.iv
}

func (m *CFB) Encrypt(p *padding.Padding) ([]byte, error) {
	return nil, nil
}

func (m *CFB) Decrypt(p *padding.Padding) ([]byte, error) {
	return nil, nil
}

func (m *CFB) Name() string {
	return m.name
}
