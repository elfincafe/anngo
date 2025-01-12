// Zero padding
package anngo

import (
	"bytes"
)

func (p zeroPadding) Pad(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return src
	}
	count := BlockSize - length%BlockSize
	dst := make([]byte, length+count)
	copy(dst, src)
	padding := bytes.Repeat([]byte{0x00}, count)
	copy(dst[length:], padding)
	return dst
}

func (p zeroPadding) Unpad(src []byte) []byte {
	length := len(src)
	if length == 0 || length%BlockSize != 0 {
		return src
	}
	lastIdx := length - 1
	for i := 0; i < BlockSize+1; i++ {
		if src[lastIdx] != 0x00 {
			break
		}
		lastIdx -= 1
	}
	dst := make([]byte, len(src[:lastIdx+1]))
	copy(dst, src[:lastIdx+1])
	return dst
}
