// PKCS#7
package anngo

import (
	"bytes"
)

func (p pkcs7Padding) Pad(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return src
	}
	count := BlockSize - length%BlockSize
	if count == 0 {
		count = BlockSize
	}
	dst := make([]byte, length+count)
	copy(dst, src)
	padding := bytes.Repeat([]byte{byte(count)}, count)
	copy(dst[length:], padding)

	return dst
}

func (p pkcs7Padding) Unpad(src []byte) []byte {
	length := len(src)
	if length == 0 || length%BlockSize != 0 {
		return src
	}
	last := src[length-1]
	if last < 0x01 || last > 0x10 {
		return src
	}
	suffix := bytes.Repeat([]byte{last}, int(last))
	idx := length - len(suffix)
	if !bytes.Equal(suffix, src[idx:]) {
		return src
	}

	dst := make([]byte, len(src[:idx]))
	copy(dst, src[:idx])
	return dst
}
