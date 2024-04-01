package padding

import (
	"bytes"
	"errors"
)

type ANSIX923 struct {
	name   string
	buffer []byte
}

func NewAnsiX923(buffer []byte) *ANSIX923 {
	p := new(ANSIX923)
	p.buffer = make([]byte, len(buffer))
	copy(p.buffer, buffer)
	return p
}

func (p *ANSIX923) Pad(BlockSize int) ([]byte, error) {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return p.buffer, nil
	}
	// Padding
	b := p.buffer[len(p.buffer)-1]
	if _, ok := byteMap2[b]; !ok {
		return nil, errors.New("")
	}
	pad := append(bytes.Repeat([]byte{0x00}, size-1), b)
	p.buffer = append(p.buffer, pad...)
	return p.buffer, nil
}

func (p *ANSIX923) Unpad(BlockSize int) ([]byte, error) {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return p.buffer, nil
	}
	// Unpadding
	b := p.buffer[len(p.buffer)-1]
	unpad := append(bytes.Repeat([]byte{0x00}, size-1), b)
	idx := bytes.Index(p.buffer, unpad)
	if idx == -1 {
		return nil, errors.New(`Can't find ANSI X932 padding`)
	}
	p.buffer = p.buffer[:idx]
	return p.buffer, nil
}

func (p *ANSIX923) Name() string {
	return p.name
}
