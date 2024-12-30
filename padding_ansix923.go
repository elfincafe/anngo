// ANSI X9.23
package anngo

import (
	"bytes"
)

func NewAnsiX923() ANSIX923 {
	p := ANSIX923{}
	return p
}

func (p ANSIX923) Pad(src []byte) []byte {
	length := len(src)
	count := BlockSize - length%BlockSize
	if count >= BlockSize || count <= 0 {
		return src
	}
	padding := append(bytes.Repeat([]byte{0x00}, count-1), byte(count))
	dst := make([]byte, length+count)
	copy(dst, src)
	copy(dst[length:], padding)
	return dst
}

func (p ANSIX923) Unpad(src []byte) []byte {
	length := len(src)
	count := length % BlockSize
	if count != 0 || length == 0 {
		return src
	}
	last := src[length-1]
	if last < 0x01 || last > 0x0f {
		return src
	}
	suffix := append(bytes.Repeat([]byte{0x00}, int(last)-1), last)
	idx := length - len(suffix)
	if !bytes.Equal(suffix, src[idx:]) {
		return src
	}

	dst := make([]byte, len(src[:idx]))
	copy(dst, src[:idx])
	return dst
}
