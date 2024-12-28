package anngo

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewZero(t *testing.T) {
	p := NewZero()
	v := reflect.TypeOf(p)
	if v.Kind() != reflect.Struct {
		t.Errorf("Padding Type: %v, Expected: %v", v.Kind(), reflect.Struct)
	} else if v.Name() != "ZERO" {
		t.Errorf("Padding Name: %v, Expected: %v", v.Name(), "ZERO")
	}
}

func TestZeroPad(t *testing.T) {
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
			expected: append([]byte("0123456789abcdefg"), bytes.Repeat([]byte{0x00}, 15)...),
		},
		{
			s:        []byte("0123456789abcdefgh"),
			expected: append([]byte("0123456789abcdefgh"), bytes.Repeat([]byte{0x00}, 14)...),
		},
		{
			s:        []byte("0123456789abcdefghijklmnopqrst"),
			expected: append([]byte("0123456789abcdefghijklmnopqrst"), []byte{0x00, 0x00}...),
		},
		{
			s:        []byte("0123456789abcdefghijklmnopqrstu"),
			expected: append([]byte("0123456789abcdefghijklmnopqrstu"), []byte{0x00}...),
		},
	}
	p := NewZero()
	for i, c := range cases {
		r := p.Pad(c.s)
		if !bytes.Equal(r, c.expected) {
			t.Errorf("[%d] Pad\n  Result  : %v\n  Expected: %v", i, r, c.expected)
		}
	}
}

func TestZeroUnpad(t *testing.T) {
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
			s:        append([]byte("0123456789abcdefg"), bytes.Repeat([]byte{0x00}, 15)...),
			expected: []byte("0123456789abcdefg"),
		},
		{
			s:        append([]byte("0123456789abcdefgh"), bytes.Repeat([]byte{0x00}, 14)...),
			expected: []byte("0123456789abcdefgh"),
		},
		{
			s:        append([]byte("0123456789abcdefghijklmnopqrst"), []byte{0x00, 0x00}...),
			expected: []byte("0123456789abcdefghijklmnopqrst"),
		},
		{
			s:        append([]byte("0123456789abcdefghijklmnopqrstu"), []byte{0x00}...),
			expected: []byte("0123456789abcdefghijklmnopqrstu"),
		},
	}
	p := NewZero()
	for i, c := range cases {
		r := p.Unpad(c.s)
		if !bytes.Equal(r, c.expected) {
			t.Errorf("[%d] Unpad\n  Result  : %v\n  Expected: %v", i, r, c.expected)
		}
	}
}
