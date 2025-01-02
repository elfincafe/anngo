// ISO 10126
package anngo

import (
	"crypto/rand"
)

func NewIso10126() ISO10126 {
	p := ISO10126{}
	return p
}

func (p ISO10126) Pad(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return src
	}
	count := BlockSize - length%BlockSize
	b := make([]byte, count)
	_, _ = rand.Read(b)
	b[count-1] = byte(count)
	padding := b

	dst := make([]byte, length+count)
	copy(dst, src)
	copy(dst[length:], padding)
	return dst
}

func (p ISO10126) Unpad(src []byte) []byte {
	length := len(src)
	if length == 0 || length%BlockSize != 0 {
		return src
	}
	last := src[length-1]
	if last < 0x01 || last > 0x10 {
		return src
	}
	idx := length - int(last)
	dst := make([]byte, idx)
	copy(dst, src[:idx])
	return dst
}
