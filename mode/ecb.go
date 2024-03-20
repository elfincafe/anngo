package mode

import (
	"anngo/padding"
)

type ECB struct {
	padding *padding.Padding
}

func NewECB(p *padding.Padding) *ECB {
	m := new(ECB)
	return m
}
