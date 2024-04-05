package anngo

import (
	"bytes"
	"testing"
)

func TestGenerate(t *testing.T) {
	cases := []struct {
		blockSize int
	}{
		{128},
		{192},
		{256},
		{123},
	}
	for k, v := range cases {
		b := Generate(v.blockSize)
		if len(b) != v.blockSize {
			t.Errorf(`[Case%d] %d (%d)`, k, len(b), v.blockSize)
		}
	}
}

func TestResize(t *testing.T) {
	b := []byte("%3l|YQrC5Rk],+oDnOUd7Zp-*_J.x{(I^tabe@0wjNTzVG[ucF8/2HsX6M)4ym~fBh$#Eg1!KL9PASiv&}Wq")
	cases := []struct {
		blockSize int
		value     []byte
		expected  []byte
	}{
		{
			128,
			[]byte(b[10:26]),
			[]byte(b[10:26]),
		},
		{
			128,
			[]byte(b[5:17]),
			append([]byte(b[5:17]), []byte{0x00, 0x00, 0x00, 0x00}...),
		},
		{
			128,
			[]byte(b[20:40]),
			[]byte{0x25, 0x30, 0x30, 0x30, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24},
		},
		{
			192,
			[]byte(b[63:87]),
			[]byte(b[63:87]),
		},
		{
			192,
			[]byte(b[55:76]),
			append([]byte(b[55:76]), []byte{0x00, 0x00, 0x00}...),
		},
		{
			192,
			[]byte(b[32:76]),
			[]byte{0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x68, 0x68, 0x68, 0x68, 0x68, 0x68, 0x68, 0x68, 0x78, 0x78, 0x78, 0x78, 0x78, 0x35, 0x36, 0x37, 0x38},
		},
		{
			256,
			[]byte(b[0:32]),
			[]byte(b[0:32]),
		},
		{
			256,
			[]byte(b[47:77]),
			append([]byte(b[47:77]), []byte{0x00, 0x00}...),
		},
		{
			256,
			[]byte(b[:]),
			[]byte{0x0c, 0x7b, 0x5c, 0x47, 0x63, 0x78, 0x6e, 0x71, 0x72, 0x3c, 0x19, 0x29, 0x22, 0x32, 0x34, 0x31, 0x7c, 0x74, 0x49, 0x73, 0x40, 0x30, 0x46, 0x5c, 0x2e, 0x3b, 0x4d, 0x55, 0x41, 0x5a, 0x57, 0x5d},
		},
	}
	for k, v := range cases {
		ret := Resize(v.value, v.blockSize)
		if !bytes.Equal(ret, v.expected) {
			t.Errorf("[Case%d] %v (%v)", k, ret, v.expected)
		}
	}
}
