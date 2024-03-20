package padding

import (
	"bytes"
	"fmt"
)

type PKCS7 struct {
	paddingBase
}

func NewPkcs7(buffer []byte, blockSize int) *PKCS7 {
	p := new(PKCS7)
	copy(p.Buffer, buffer)
	p.BlockSize = blockSize
	return p
}

func (p *PKCS7) Pad() error {
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
	pad := bytes.Repeat([]byte{byteMap1[size]}, size)
	p.Buffer = append(p.Buffer, pad...)

	return nil
}

func (p *PKCS7) Unpad() error {
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
	idx := bytes.Index(p.Buffer, bytes.Repeat([]byte{b}, size))
	p.Buffer = p.Buffer[:idx]
	return nil
}
