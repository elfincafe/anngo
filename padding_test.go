package anngo

import (
	"bytes"
	"testing"
)

func TestPKCS7Pad(t *testing.T) {
	cases := []struct {
		blockSize int
		buffer    []byte
		expected  []byte
	}{
		{
			16,
			[]byte("abcdefghijklmnop"),
			[]byte("abcdefghijklmnop"),
		},
		{
			16,
			[]byte("abcdefghijklm"),
			append([]byte("abcdefghijklm"), []byte{0x03, 0x03, 0x03}...),
		},
		{
			24,
			[]byte("abcdefghijklmnopqrstuvwx"),
			[]byte("abcdefghijklmnopqrstuvwx"),
		},
		{
			24,
			[]byte("abcdefghijklmnopqrst"),
			append([]byte("abcdefghijklmnopqrst"), []byte{0x04, 0x04, 0x04, 0x04}...),
		},
		{
			32,
			[]byte("abcdefghijklmnopqrstuvwxyz123456"),
			[]byte("abcdefghijklmnopqrstuvwxyz123456"),
		},
		{
			32,
			[]byte("abcdefghijklmnopqrstuvwxyz1"),
			append([]byte("abcdefghijklmnopqrstuvwxyz1"), []byte{0x05, 0x05, 0x05, 0x05, 0x05}...),
		},
	}
	for k, v := range cases {
		p := &PaddingPKCS7{paddingBase{v.blockSize, v.buffer}}
		res, _ := p.Pad()
		if !bytes.Equal(res, v.expected) {
			t.Errorf(`[Case%d] %v (%v)`, k, res, v.buffer)
		}
	}
}

func TestPKCS7Unpad(t *testing.T) {

}

func TestZerosPad(t *testing.T) {

}

func TestZerosUnpad(t *testing.T) {

}

func TestAnsiX923Pad(t *testing.T) {

}

func TestAnsiX923Unpad(t *testing.T) {

}
func TestIso10126Pad(t *testing.T) {

}

func TestIso10126Unpad(t *testing.T) {

}
