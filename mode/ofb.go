package mode

import "anngo/padding"

type OFB struct {
	name string
	iv   []byte
}

func NewOFB(iv []byte) *OFB {
	m := new(OFB)
	m.name = "OFB"
	copy(m.iv, iv)
	return m
}

func (m *OFB) IV() []byte {
	return m.iv
}

func (m *OFB) Encrypt(p *padding.Padding) ([]byte, error) {
	return nil, nil
}

func (m *OFB) Decrypt(p *padding.Padding) ([]byte, error) {
	return nil, nil
}

func (m *OFB) Name() string {
	return m.name
}
