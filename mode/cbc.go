package mode

import (
	"anngo/padding"
)

type CBC struct {
	padding *padding.Padding
	iv      []byte
}

func NewCBC(p *padding.Padding, iv []byte) *CBC {
	m := new(CBC)
	copy(m.iv, iv)
	return m
}
