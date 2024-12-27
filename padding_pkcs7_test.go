package anngo

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewPkcs7(t *testing.T) {
	p := NewPkcs7()
	v := reflect.TypeOf(p)
	if v.Kind() != reflect.Pointer {
		t.Errorf("Padding Type: %v, Expected: %v", v.Kind(), reflect.Pointer)
	} else if v.Elem().Name() != "PKCS7" {
		t.Errorf("Padding Name: %v, Expected: %v", v.Elem().Name(), "PKCS7")
	}
}

func TestPkcs7Pad(t *testing.T) {
	cases := []struct {
		s        []byte
		expected []byte
	}{
		{
			s:        []byte{},
			expected: []byte{},
		},
		{
			s:        []byte("0123456789abcdef"),
			expected: []byte("0123456789abcdef"),
		},
		{
			s:        []byte("0123456789abcdefg"),
			expected: append([]byte("0123456789abcdefg"), bytes.Repeat([]byte{0x0f}, 15)...),
		},
		{
			s:        []byte("0123456789abcdefgh"),
			expected: append([]byte("0123456789abcdefgh"), bytes.Repeat([]byte{0x0e}, 14)...),
		},
		{
			s:        []byte("0123456789abcdefghijklmnopqrst"),
			expected: append([]byte("0123456789abcdefghijklmnopqrst"), []byte{0x02, 0x02}...),
		},
		{
			s:        []byte("0123456789abcdefghijklmnopqrstu"),
			expected: append([]byte("0123456789abcdefghijklmnopqrstu"), []byte{0x01}...),
		},
	}
	p := NewPkcs7()
	for i, c := range cases {
		r := p.Pad(c.s)
		if !bytes.Equal(r, c.expected) {
			t.Errorf("[%d] Pad\n  Result  : %v\n  Expected: %v", i, r, c.expected)
		}
	}
}

func TestPkcs7Unpad(t *testing.T) {
	cases := []struct {
		s        []byte
		expected []byte
	}{
		{
			s:        []byte{},
			expected: []byte{},
		},
		{
			s:        []byte("0123456789"),
			expected: []byte("0123456789"),
		},
		{
			s:        []byte("0123456789abcdef"),
			expected: []byte("0123456789abcdef"),
		},
		{
			s:        append([]byte("0123456789abcdefg"), bytes.Repeat([]byte{0x0f}, 15)...),
			expected: []byte("0123456789abcdefg"),
		},
		{
			s:        append([]byte("0123456789abcdefgh"), bytes.Repeat([]byte{0x0e}, 14)...),
			expected: []byte("0123456789abcdefgh"),
		},
		{
			s:        append([]byte("0123456789abcdefghijklmnopqrst"), []byte{0x02, 0x02}...),
			expected: []byte("0123456789abcdefghijklmnopqrst"),
		},
		{
			s:        append([]byte("0123456789abcdefghijklmnopqrstu"), []byte{0x01}...),
			expected: []byte("0123456789abcdefghijklmnopqrstu"),
		},
	}
	p := NewPkcs7()
	for i, c := range cases {
		r := p.Unpad(c.s)
		if !bytes.Equal(r, c.expected) {
			t.Errorf("[%d] Unpad\n  Result  : %v\n  Expected: %v", i, r, c.expected)
		}
	}
}
