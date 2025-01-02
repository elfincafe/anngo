// Zero padding
package anngo

import (
	"bytes"
)

func NewZero() ZERO {
	p := ZERO{}
	return p
}

func (p ZERO) Pad(src []byte) []byte {
	length := len(src)
	count := BlockSize - length%BlockSize
	if count >= BlockSize || count <= 0 {
		return src
	}
	dst := make([]byte, length+count)
	copy(dst, src)
	padding := bytes.Repeat([]byte{0x00}, count)
	copy(dst[length:], padding)
	return dst
}

func (p ZERO) Unpad(src []byte) []byte {
	length := len(src)
	count := length % BlockSize
	if count != 0 || length == 0 {
		return src
	}
	idx := length - 1
	for i := 0; i < BlockSize; i++ {
		if src[idx-i] != 0x00 {
			idx -= i
			break
		}
	}
	dst := make([]byte, len(src[:idx+1]))
	copy(dst, src[:idx+1])
	return dst
}
