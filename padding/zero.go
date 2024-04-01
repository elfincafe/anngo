package padding

import (
	"bytes"
	"errors"
)

type Zero struct {
	name   string
	buffer []byte
}

func NewZero(buffer []byte) *Zero {
	p := new(Zero)
	p.buffer = make([]byte, len(buffer))
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
	blockBytes := BlockSize / 8
	length := len(p.buffer)
	if length%blockBytes != 0 {
		return nil, errors.New("byte size mismatch")
	}
	// Unpadding
	idx := length - 1
	limit := length - blockBytes + 1
	for i := len(p.buffer) - 1; i >= limit; i-- {
		if p.buffer[i] != 0x00 {
			idx = i + 1
			break
		}
	}
	return p.buffer[:idx], nil
}

func (p *Zero) Name() string {
	return p.name
}
