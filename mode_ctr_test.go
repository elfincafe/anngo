package anngo

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestNewCTR(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	m := NewCTR(b[:16])
	v := reflect.TypeOf(m)
	if v.Kind() != reflect.Pointer {
		t.Errorf("Mode: %v, Expected: %v", v.Kind(), reflect.Pointer)
	} else if v.Elem().Name() != "CTR" {
		t.Errorf("Mode Name: %v, Expected: %v", v.Name(), "CTR")
	}
}

func TestCTREncrypt(t *testing.T) {
	// Case
	cases := []struct {
		key      []byte
		data     []byte
		iv       []byte
		expected []byte
	}{
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96, 24},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96, 24, 56},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96, 24, 56, 74},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159, 145},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159, 145, 73},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159, 145, 73, 185},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122, 9},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122, 9, 38},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122, 9, 38, 132},
		},
	}
	// Test
	for i, c := range cases {
		m := NewCTR(c.key)
		m.SetIV(c.iv)
		ret, _ := m.Encrypt(c.data)
		if !bytes.Equal(ret, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, ret, c.expected)
		}
	}
}

func TestCTRDecrypt(t *testing.T) {
	// Case
	cases := []struct {
		key      []byte
		data     []byte
		iv       []byte
		expected []byte
	}{
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96, 24},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96, 24, 56},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96, 24, 56, 74},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159, 145},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159, 145, 73},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159, 145, 73, 185},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122, 9},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122, 9, 38},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122, 9, 38, 132},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnopqr"),
		},
	}
	// Test
	for i, c := range cases {
		m := NewCTR(c.key)
		m.SetIV(c.iv)
		ret, _ := m.Decrypt(c.data)
		if !bytes.Equal(ret, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, ret, c.expected)
		}
	}
}

func TestCTRIV(t *testing.T) {
	b := make([]byte, BlockSize)
	rand.Read(b)
	m := NewCTR(b[:BlockSize])
	if !bytes.Equal(m.iv, m.IV()) {
		t.Errorf("Result:   %v\nExpected: %v\n", m.IV(), m.iv)
	}
}

func TestCTRSetIV(t *testing.T) {
	// Case
	b := make([]byte, 128)
	rand.Read(b)
	cases := []struct {
		iv       []byte
		expected []byte
	}{
		{iv: b[:16], expected: b[:16]},
	}
	// Test
	m := NewCTR(b[16:32])
	for i, c := range cases {
		m.SetIV(c.iv)
		if !bytes.Equal(m.iv, c.iv) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, m.iv, c.expected)
		}
	}
}
