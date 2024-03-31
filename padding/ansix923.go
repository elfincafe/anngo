package padding

import (
	"bytes"
	"fmt"
)

type ANSIX923 struct {
	name   string
	buffer []byte
}

func NewAnsiX923(buffer []byte) *ANSIX923 {
	p := new(ANSIX923)
	copy(p.buffer, buffer)
	return p
}

func (p *ANSIX923) Pad(BlockSize int) error {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return nil
	}
	// Padding
	b := p.buffer[len(p.buffer)-1]
	if _, ok := byteMap2[b]; !ok {
		return nil
	}
	pad := append(bytes.Repeat([]byte{0x00}, size-1), b)
	p.buffer = append(p.buffer, pad...)
	return nil
}

func (p *ANSIX923) Unpad(BlockSize int) error {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return nil
	}
	// Unpadding
	b := p.buffer[len(p.buffer)-1]
	unpad := append(bytes.Repeat([]byte{0x00}, size-1), b)
	idx := bytes.Index(p.buffer, unpad)
	if idx == -1 {
		return fmt.Errorf(`Padding isn't ANSI X932`)
	}
	p.buffer = p.buffer[:idx]
	return nil
}

func (p *ANSIX923) Name() string {
	return p.name
}
