package mode

import "anngo/padding"

type CTR struct {
	name string
}

func NewCTR() *CTR {
	m := new(CTR)
	m.name = "CTR"
	return m
}

func (m *CTR) Encrypt(p *padding.Padding) ([]byte, error) {
	return nil, nil
}

func (m *CTR) Decrypt(p *padding.Padding) ([]byte, error) {
	return nil, nil
}

func (m *CTR) Name() string {
	return m.name
}
