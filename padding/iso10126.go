package padding

import (
	"crypto/rand"
	"fmt"
)

type ISO10126 struct {
	paddingBase
}

func NewIso10126(buffer []byte, blockSize int) *ISO10126 {
	p := new(ISO10126)
	copy(p.Buffer, buffer)
	p.BlockSize = blockSize
	return p
}

func (p *ISO10126) Pad() error {
	// Block Size
	if isValidBlockSize(p.BlockSize) {
		return fmt.Errorf(`Invalid block size "%d".`, p.BlockSize)
	}
	// Padding Size
	size := paddingLength(p.BlockSize, len(p.Buffer))
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
	p.Buffer = append(p.Buffer, pad...)
	return nil
}

func (p *ISO10126) Unpad() error {
	// Block Size
	if isValidBlockSize(p.BlockSize) {
		return fmt.Errorf(`Invalid block size "%d".`, p.BlockSize)
	}
	// Padding Size
	size := paddingLength(p.BlockSize, len(p.Buffer))
	if size == 0 {
		return nil
	}
	// Unpadding
	b := p.Buffer[len(p.Buffer)-1]
	if _, ok := byteMap2[b]; !ok {
		return nil
	}
	idx := byteMap2[b]
	p.Buffer = p.Buffer[:idx]

	return nil
}
