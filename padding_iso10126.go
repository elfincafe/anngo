// ISO 10126
package anngo

import (
	"crypto/rand"
)

func NewIso10126() ISO10126 {
	p := ISO10126{}
	return p
}

func (p ISO10126) Pad(s []byte) []byte {
	length := len(s)
	count := BlockSize - length%BlockSize
	if count >= BlockSize || count <= 0 {
		return s
	}
	b := make([]byte, count)
	_, _ = rand.Read(b)
	b[count-1] = byte(count)
	padding := b

	return append(s, padding...)
}

func (p ISO10126) Unpad(s []byte) []byte {
	length := len(s)
	count := length % BlockSize
	if count != 0 || length == 0 {
		return s
	}
	last := s[length-1]
	if last < 0x01 || last > 0x0f {
		return s
	}
	idx := length - int(last)
	return s[:idx]
}
