package padding

import (
	"bytes"
	"fmt"
)

type ANSIX923 struct {
	paddingBase
}

func NewAnsiX923(buffer []byte, blockSize int) *ANSIX923 {
	p := new(ANSIX923)
	copy(p.Buffer, buffer)
	p.BlockSize = blockSize
	return p
}

func (p *ANSIX923) Pad() error {
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
	b := p.Buffer[len(p.Buffer)-1]
	if _, ok := byteMap2[b]; !ok {
		return nil
	}
	pad := append(bytes.Repeat([]byte{0x00}, size-1), b)
	p.Buffer = append(p.Buffer, pad...)
	return nil
}

func (p *ANSIX923) Unpad() error {
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
	unpad := append(bytes.Repeat([]byte{0x00}, size-1), b)
	idx := bytes.Index(p.Buffer, unpad)
	if idx == -1 {
		return fmt.Errorf(`Padding isn't ANSI X932`)
	}
	p.Buffer = p.Buffer[:idx]
	return nil
}
