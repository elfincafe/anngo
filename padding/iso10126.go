package padding

import (
	"crypto/rand"
	"errors"
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

func (p *ISO10126) Pad(BlockSize int) ([]byte, error) {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return p.buffer, nil
	}
	// Padding
	pad := make([]byte, size)
	_, err := rand.Read(pad)
	if err != nil {
		return nil, err
	}
	pad[size-1] = byteMap1[size]
	p.buffer = append(p.buffer, pad...)
	return p.buffer, nil
}

func (p *ISO10126) Unpad(BlockSize int) ([]byte, error) {
	// Padding Size
	size := paddingLength(BlockSize, len(p.buffer))
	if size == 0 {
		return p.buffer, nil
	}
	// Unpadding
	b := p.buffer[len(p.buffer)-1]
	if _, ok := byteMap2[b]; !ok {
		return nil, errors.New("Can't find ISO10126 padding")
	}
	idx := byteMap2[b]
	p.buffer = p.buffer[:idx]

	return p.buffer, nil
}

func (p *ISO10126) Name() string {
	return p.name
}
