package mode

import (
	"anngo/padding"
)

type ECB struct {
	name string
}

func NewECB() *ECB {
	m := new(ECB)
	m.name = "ECB"
	return m
}

func (m *ECB) Encrypt(p *padding.Padding) ([]byte, error) {
	return nil, nil
}

func (m *ECB) Decrypt(p *padding.Padding) ([]byte, error) {
	return nil, nil
}

func (m *ECB) Name() string {
	return m.name
}
