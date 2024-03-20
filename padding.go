package anngo

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
)

const (
	AES128 = 128
	AES192 = 192
	AES256 = 256
)

var (
	byteMap1 = map[int]byte{
		0: 0x00, 1: 0x01, 2: 0x02, 3: 0x03, 4: 0x04,
		5: 0x05, 6: 0x06, 7: 0x07, 8: 0x08, 9: 0x09,
		10: 0x0a, 11: 0x0b, 12: 0x0c, 13: 0x0d, 14: 0x0e,
		15: 0x0f, 16: 0x10, 17: 0x11, 18: 0x12, 19: 0x13,
		20: 0x14, 21: 0x15, 22: 0x16, 23: 0x17, 24: 0x18,
		25: 0x19, 26: 0x1a, 27: 0x1b, 28: 0x1c, 29: 0x1d,
		30: 0x1e, 31: 0x1f,
	}
	byteMap2 = map[byte]int{
		0x00: 0, 0x01: 1, 0x02: 2, 0x03: 3, 0x04: 4,
		0x05: 5, 0x06: 6, 0x07: 7, 0x08: 8, 0x09: 9,
		0x0a: 10, 0x0b: 11, 0x0c: 12, 0x0d: 13, 0x0e: 14,
		0x0f: 15, 0x10: 16, 0x11: 17, 0x12: 18, 0x13: 19,
		0x14: 20, 0x15: 21, 0x16: 22, 0x17: 23, 0x18: 24,
		0x19: 25, 0x1a: 26, 0x1b: 27, 0x1c: 28, 0x1d: 29,
		0x1e: 30, 0x1f: 31,
	}
)

type Padding interface {
	Pad() error
	Unpad() error
}

type paddingBase struct {
	blockSize int
	buffer    []byte
	bitMap1   map[int]byte
	bitMap2   map[byte]int
}

type Pkcs7 struct {
	paddingBase
}

type Zero struct {
	paddingBase
}

type AnsiX923 struct {
	paddingBase
}

type Iso10126 struct {
	paddingBase
}

func paddingLength(blockSize, length int) int {
	return int(math.Ceil(float64(length)/float64(blockSize)))*blockSize - length
}

func isValidBlockSize(blockSize int) error {
	if blockSize != AES128 && blockSize != AES192 && blockSize != AES256 {
		return fmt.Errorf(`Invalid block size %d.`, blockSize)
	}
	return nil
}

func NewPkcs7(buffer []byte, blockSize int) *Pkcs7 {
	p := new(Pkcs7)
	copy(p.buffer, buffer)
	p.blockSize = blockSize
	return p
}

func (p *Pkcs7) Pad() error {
	// Block Size
	err := isValidBlockSize(p.blockSize)
	if err != nil {
		return err
	}
	// Padding Size
	size := paddingLength(p.blockSize, len(p.buffer))
	if size == 0 {
		return nil
	}
	// Padding
	pad := bytes.Repeat([]byte{byteMap1[size]}, size)
	p.buffer = append(p.buffer, pad...)

	return nil
}

func (p *Pkcs7) Unpad() error {
	// Block Size
	err := isValidBlockSize(p.blockSize)
	if err != nil {
		return err
	}
	// Padding Size
	size := paddingLength(p.blockSize, len(p.buffer))
	if size == 0 {
		return nil
	}
	// Unpadding
	b := p.buffer[len(p.buffer)-1]
	if _, ok := byteMap2[b]; !ok {
		return nil
	}
	idx := bytes.Index(p.buffer, bytes.Repeat([]byte{b}, size))
	p.buffer = p.buffer[:idx]
	return nil
}

func NewZero(buffer []byte, blockSize int) *Zero {
	p := new(Zero)
	copy(p.buffer, buffer)
	p.blockSize = blockSize
	p.bitMap1, p.bitMap2 = createBitMap()
	return p
}

func (p *Zero) Pad() error {
	// Block Size
	err := isValidBlockSize(p.blockSize)
	if err != nil {
		return err
	}
	// Padding Size
	size := paddingLength(p.blockSize, len(p.buffer))
	if size == 0 {
		return nil
	}
	// Padding
	pad := bytes.Repeat([]byte{0x00}, size)
	p.buffer = append(p.buffer, pad...)
	return nil
}

func (p *Zero) Unpad() error {
	// Block Size
	err := isValidBlockSize(p.blockSize)
	if err != nil {
		return err
	}
	// Padding Size
	size := paddingLength(p.blockSize, len(p.buffer))
	if size == 0 {
		return nil
	}
	// Unpadding
	idx := len(p.buffer)
	for i := len(p.buffer) - 1; i >= 0; i-- {
		if p.buffer[i] != 0x00 {
			idx = i
		}
	}
	p.buffer = p.buffer[:idx]
	return nil
}

func NewAnsiX923(buffer []byte, blockSize int) *AnsiX923 {
	p := new(AnsiX923)
	copy(p.buffer, buffer)
	p.blockSize = blockSize
	p.bitMap1, p.bitMap2 = createBitMap()
	return p
}

func (p *AnsiX923) Pad() error {
	// Block Size
	err := isValidBlockSize(p.blockSize)
	if err != nil {
		return err
	}
	// Padding Size
	size := paddingLength(p.blockSize, len(p.buffer))
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

func (p *AnsiX923) Unpad() error {
	// Block Size
	err := isValidBlockSize(p.blockSize)
	if err != nil {
		return err
	}
	// Padding Size
	size := paddingLength(p.blockSize, len(p.buffer))
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

func NewIso10126(buffer []byte, blockSize int) *Iso10126 {
	p := new(Iso10126)
	copy(p.buffer, buffer)
	p.blockSize = blockSize
	p.bitMap1, p.bitMap2 = createBitMap()
	return p
}

func (p *Iso10126) Pad() error {
	// Block Size
	err := isValidBlockSize(p.blockSize)
	if err != nil {
		return err
	}
	// Padding Size
	size := paddingLength(p.blockSize, len(p.buffer))
	if size == 0 {
		return nil
	}
	// Padding
	pad := make([]byte, size)
	_, err = rand.Read(pad)
	if err != nil {
		return err
	}
	pad[size-1] = byteMap1[size]
	p.buffer = append(p.buffer, pad...)
	return nil
}

func (p *Iso10126) Unpad() error {
	// Block Size
	err := isValidBlockSize(p.blockSize)
	if err != nil {
		return err
	}
	// Padding Size
	size := paddingLength(p.blockSize, len(p.buffer))
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
