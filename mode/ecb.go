package mode

import (
	"anngo/padding"
)

type ECB struct {
	name string
}

func NewECB(p *padding.Padding) *ECB {
	m := new(ECB)
	m.name = "ECB"
	return m
}

func (m *ECB) Encrypt() ([]byte, error) {
	return nil, nil
}

func (m *ECB) Decrypt() ([]byte, error) {
	return nil, nil
}

func (m *ECB) Name() string {
	return m.name
}
