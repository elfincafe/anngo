package mode

import (
	"anngo/padding"
)

type CTR struct {
	padding *padding.Padding
}

func NewCTR(p *padding.Padding) *CTR {
	m := new(CTR)
	return m
}
