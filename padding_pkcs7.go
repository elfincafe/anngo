// PKCS#7
package anngo

import "bytes"

func NewPkcs7() *PKCS7 {
	p := new(PKCS7)
	return p
}

func (p *PKCS7) Pad(s []byte) []byte {
	length := len(s)
	count := BlockSize - length%BlockSize
	if count >= BlockSize || count <= 0 {
		return s
	}
	padding := bytes.Repeat([]byte{byte(count)}, count)

	return append(s, padding...)
}

func (p *PKCS7) Unpad(s []byte) []byte {
	length := len(s)
	count := length % BlockSize
	if count != 0 || length == 0 {
		return s
	}
	last := s[length-1]
	if last < 0x01 || last > 0x0f {
		return s
	}
	idx := length - 1
	for i := 0; i < BlockSize; i++ {
		if s[idx-i] != last {
			idx -= i
			break
		}
	}

	return s[:idx+1]
}
