package padding

import (
	"crypto/rand"
)

type ISO10126 struct {
	name   string
	buffer []byte
}

func NewIso10126(buffer []byte) *ISO10126 {
	p := new(ISO10126)
	copy(p.buffer, buffer)
	return p
}

func (p *ISO10126) Pad(BlockSize int) error {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return nil
	}
	// Padding
	pad := make([]byte, size)
	_, err := rand.Read(pad)
	if err != nil {
		return err
	}
	pad[size-1] = byteMap1[size]
	p.buffer = append(p.buffer, pad...)
	return nil
}

func (p *ISO10126) Unpad(BlockSize int) error {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return nil
	}
	// Unpadding
	b := p.buffer[len(p.buffer)-1]
	if _, ok := byteMap2[b]; !ok {
		return nil
	}
	idx := byteMap2[b]
	p.buffer = p.buffer[:idx]

	return nil
}

func (p *ISO10126) Name() string {
	return p.name
}
