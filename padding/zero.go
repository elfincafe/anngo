package padding

import (
	"bytes"
	"fmt"
)

type Zero struct {
	paddingBase
}

func NewZero(buffer []byte, blockSize int) *Zero {
	p := new(Zero)
	copy(p.Buffer, buffer)
	p.BlockSize = blockSize
	return p
}

func (p *Zero) Pad() error {
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
	pad := bytes.Repeat([]byte{0x00}, size)
	p.Buffer = append(p.Buffer, pad...)
	return nil
}

func (p *Zero) Unpad() error {
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
	idx := len(p.Buffer)
	for i := len(p.Buffer) - 1; i >= 0; i-- {
		if p.Buffer[i] != 0x00 {
			idx = i
		}
	}
	p.Buffer = p.Buffer[:idx]
	return nil
}
