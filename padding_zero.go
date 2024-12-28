// Zero padding
package anngo

import (
	"bytes"
)

func NewZero() ZERO {
	p := ZERO{}
	return p
}

func (p ZERO) Pad(s []byte) []byte {
	length := len(s)
	count := BlockSize - length%BlockSize
	if count >= BlockSize || count <= 0 {
		return s
	}
	padding := bytes.Repeat([]byte{0x00}, count)

	return append(s, padding...)
}

func (p ZERO) Unpad(s []byte) []byte {
	length := len(s)
	count := length % BlockSize
	if count != 0 || length == 0 {
		return s
	}
	idx := length - 1
	for i := 0; i < BlockSize; i++ {
		if s[idx-i] != 0x00 {
			idx -= i
			break
		}
	}

	return s[:idx+1]
}
