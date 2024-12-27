package anngo

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewAnsiX923(t *testing.T) {
	p := NewAnsiX923()
	v := reflect.TypeOf(p)
	if v.Kind() != reflect.Pointer {
		t.Errorf("Padding Type: %v, Expected: %v", v.Kind(), reflect.Pointer)
	} else if v.Elem().Name() != "ANSIX923" {
		t.Errorf("Padding Name: %v, Expected: %v", v.Elem().Name(), "ANSIX923")
	}
}

func TestAnsiX923Pad(t *testing.T) {
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
			expected: append(append([]byte("0123456789abcdefg"), bytes.Repeat([]byte{0x00}, 14)...), []byte{0x0f}...),
		},
		{
			s:        []byte("0123456789abcdefgh"),
			expected: append(append([]byte("0123456789abcdefgh"), bytes.Repeat([]byte{0x00}, 13)...), []byte{0x0e}...),
		},
		{
			s:        []byte("0123456789abcdefghijklmnopqrst"),
			expected: append([]byte("0123456789abcdefghijklmnopqrst"), []byte{0x00, 0x02}...),
		},
		{
			s:        []byte("0123456789abcdefghijklmnopqrstu"),
			expected: append([]byte("0123456789abcdefghijklmnopqrstu"), []byte{0x01}...),
		},
	}
	p := NewAnsiX923()
	for i, c := range cases {
		r := p.Pad(c.s)
		if !bytes.Equal(r, c.expected) {
			t.Errorf("[%d] Pad\n  Result  : %v\n  Expected: %v", i, r, c.expected)
		}
	}
}

func TestAnsiX923Unpad(t *testing.T) {
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
			s:        append(append([]byte("0123456789abcdefg"), bytes.Repeat([]byte{0x00}, 14)...), []byte{0x0f}...),
			expected: []byte("0123456789abcdefg"),
		},
		{
			s:        append(append([]byte("0123456789abcdefgh"), bytes.Repeat([]byte{0x00}, 13)...), []byte{0x0e}...),
			expected: []byte("0123456789abcdefgh"),
		},
		{
			s:        append([]byte("0123456789abcdefghijklmnopqrst"), []byte{0x00, 0x02}...),
			expected: []byte("0123456789abcdefghijklmnopqrst"),
		},
		{
			s:        append([]byte("0123456789abcdefghijklmnopqrstu"), []byte{0x01}...),
			expected: []byte("0123456789abcdefghijklmnopqrstu"),
		},
	}
	p := NewAnsiX923()
	for i, c := range cases {
		r := p.Unpad(c.s)
		if !bytes.Equal(r, c.expected) {
			t.Errorf("[%d] Unpad\n  Result  : %v\n  Expected: %v", i, r, c.expected)
		}
	}
}