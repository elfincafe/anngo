package padding

import (
	"bytes"
)

type Zero struct {
	name   string
	buffer []byte
}

func NewZero(buffer []byte) *Zero {
	p := new(Zero)
	copy(p.buffer, buffer)
	return p
}

func (p *Zero) Pad(BlockSize int) error {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return nil
	}
	// Padding
	pad := bytes.Repeat([]byte{0x00}, size)
	p.buffer = append(p.buffer, pad...)
	return nil
}

func (p *Zero) Unpad(BlockSize int) error {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return nil
	}
	// Unpadding
	idx := len(p.buffer)
	for i := len(p.buffer) - 1; i >= 0; i-- {
		if p.buffer[i] != 0x00 {
			idx = i
		}
	}
	p.buffer = p.buffer[:idx]
	return nil
}

func (p *Zero) Name() string {
	return p.name
}
