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

func (p *Zero) Pad(BlockSize int) ([]byte, error) {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return p.buffer, nil
	}
	// Padding
	pad := bytes.Repeat([]byte{0x00}, size)
	p.buffer = append(p.buffer, pad...)
	return p.buffer, nil
}

func (p *Zero) Unpad(BlockSize int) ([]byte, error) {
	/*
		byteSize = int(BlockSize / 8)
		size = len(buffer) % int(BlockSize / 8)
		buffer[size:]
		157 - 9 * 16 = 13
		9 * 16
		star  = int(length/BlockSize/8)
		Length: 33
		BlockSize: 16
		Shou: 2
		Rest: 1
	*/
	// Target
	idx := len(p.buffer) - len(p.buffer)%int(BlockSize/8) - 1
	target := p.buffer[idx:]

	// Unpadding
	for i := len(p.buffer) - 1; i >= 0; i-- {
		if p.buffer[i] != 0x00 {
			idx = i
		}
	}
	p.buffer = p.buffer[:idx]
	return p.buffer, nil
}

func (p *Zero) Name() string {
	return p.name
}
