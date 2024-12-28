// ANSI X9.23
package anngo

import (
	"bytes"
)

func NewAnsiX923() ANSIX923 {
	p := ANSIX923{}
	return p
}

func (p ANSIX923) Pad(s []byte) []byte {
	length := len(s)
	count := BlockSize - length%BlockSize
	if count >= BlockSize || count <= 0 {
		return s
	}
	padding := append(bytes.Repeat([]byte{0x00}, count-1), byte(count))

	return append(s, padding...)
}

func (p ANSIX923) Unpad(s []byte) []byte {
	length := len(s)
	count := length % BlockSize
	if count != 0 || length == 0 {
		return s
	}
	last := s[length-1]
	if last < 0x01 || last > 0x0f {
		return s
	}
	pattern := append(bytes.Repeat([]byte{0x00}, int(last)-1), last)
	if bytes.HasSuffix(s, pattern) {
		length = len(s) - len(pattern)
		return s[:length]
	} else {
		return s
	}
}
