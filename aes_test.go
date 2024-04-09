package anngo

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"os"
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
			[]byte{0x65, 0x1a, 0x40, 0x5a, 0x2a, 0x5f, 0x4a, 0x2e, 0x78, 0x7b, 0x28, 0x49, 0x5e, 0x74, 0x61, 0x62},
		},
		{
			192,
			[]byte(b[60:84]),
			[]byte(b[60:84]),
		},
		{
			192,
			[]byte(b[55:76]),
			append([]byte(b[55:76]), []byte{0x00, 0x00, 0x00}...),
		},
		{
			192,
			[]byte(b[32:76]),
			[]byte{0x68, 0x39, 0x48, 0x56, 0x1c, 0x2d, 0x4e, 0x11, 0x28, 0x26, 0x70, 0x59, 0x13, 0x20, 0x6a, 0x54, 0x28, 0x0a, 0x01, 0x7f, 0x32, 0x48, 0x73, 0x58},
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
			[]byte{0x39, 0x2f, 0x29, 0x3d, 0x79, 0x76, 0x73, 0x15, 0x14, 0x50, 0x06, 0x77, 0x7a, 0x6c, 0x34, 0x47, 0x2b, 0x3b, 0x6f, 0x5e, 0x32, 0x12, 0x03, 0x75, 0x1c, 0x12, 0x63, 0x1a, 0x01, 0x16, 0x56, 0x2f},
		},
	}
	for k, v := range cases {
		ret := Resize(v.value, v.blockSize)
		if !bytes.Equal(ret, v.expected) {
			t.Errorf("[Case%d] %v (%v)", k+1, ret, v.expected)
		}
	}
}

func Test(t *testing.T) {

	iv := Generate(aes.BlockSize) /* Initial Vector */
	key := Resize([]byte("Ann*Go/Example/Key"), aes.BlockSize)

	aes, err := NewAes(key, NewCBC(iv), NewPKCS7())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", err)
		os.Exit(1)
	}

	// Encrypt
	cipherText, err := aes.Encrypt([]byte("plain_text"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", err)
		os.Exit(1)
	}
	fmt.Println(cipherText)

	// Decrypt
	plainText, err := aes.Decrypt(cipherText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", err)
		os.Exit(1)
	}
	fmt.Println(plainText)
}
