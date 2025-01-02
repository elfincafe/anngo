// PKCS#7
package anngo

import (
	"bytes"
)

func NewPkcs7() PKCS7 {
	p := PKCS7{}
	return p
}

func (p PKCS7) Pad(src []byte) []byte {
	length := len(src)
	count := BlockSize - length%BlockSize
	if count >= BlockSize || count <= 0 {
		return src
	}
	dst := make([]byte, length+count)
	copy(dst, src)
	padding := bytes.Repeat([]byte{byte(count)}, count)
	copy(dst[length:], padding)

	return dst
}

func (p PKCS7) Unpad(src []byte) []byte {
	length := len(src)
	count := length % BlockSize
	if count != 0 || length == 0 {
		return src
	}
	last := src[length-1]
	if last < 0x01 || last > 0x0f {
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
