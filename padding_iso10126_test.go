package anngo

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestNewIso10126(t *testing.T) {
	p := NewIso10126()
	v := reflect.TypeOf(p)
	if v.Kind() != reflect.Pointer {
		t.Errorf("Padding Type: %v, Expected: %v", v.Kind(), reflect.Pointer)
	} else if v.Elem().Name() != "ISO10126" {
		t.Errorf("Padding Name: %v, Expected: %v", v.Elem().Name(), "ISO10126")
	}
}

func TestIso10126Pad(t *testing.T) {
	b := make([]byte, 16)
	rand.Read(b)
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
			expected: append(append([]byte("0123456789abcdefg"), b[:14]...), []byte{0x0f}...),
		},
		{
			s:        []byte("0123456789abcdefgh"),
			expected: append(append([]byte("0123456789abcdefgh"), b[:13]...), []byte{0x0e}...),
		},
		{
			s:        []byte("0123456789abcdefghijklmnopqrst"),
			expected: append(append([]byte("0123456789abcdefghijklmnopqrst"), b[:1]...), []byte{0x02}...),
		},
		{
			s:        []byte("0123456789abcdefghijklmnopqrstu"),
			expected: append([]byte("0123456789abcdefghijklmnopqrstu"), []byte{0x01}...),
		},
	}
	p := NewIso10126()
	for i, c := range cases {
		r := p.Pad(c.s)
		length := len(c.s)
		rLast := len(r) - 1
		eLast := len(c.expected) - 1
		if len(r) > 0 && (!bytes.Equal(r[:length], c.expected[:length]) || r[rLast] != c.expected[eLast]) {
			t.Errorf("[%d] Pad\n Result  : %v\n  Expected: %v", i, r, c.expected)
		}
	}
}

func TestIso10126Unpad(t *testing.T) {
	b := make([]byte, 16)
	rand.Read(b)
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
			s:        append(append([]byte("0123456789abcdefg"), b[:14]...), []byte{0x0f}...),
			expected: []byte("0123456789abcdefg"),
		},
		{
			s:        append(append([]byte("0123456789abcdefgh"), b[:13]...), []byte{0x0e}...),
			expected: []byte("0123456789abcdefgh"),
		},
		{
			s:        append(append([]byte("0123456789abcdefghijklmnopqrst"), b[:1]...), []byte{0x02}...),
			expected: []byte("0123456789abcdefghijklmnopqrst"),
		},
		{
			s:        append([]byte("0123456789abcdefghijklmnopqrstu"), []byte{0x01}...),
			expected: []byte("0123456789abcdefghijklmnopqrstu"),
		},
	}
	p := NewIso10126()
	for i, c := range cases {
		r := p.Unpad(c.s)
		if !bytes.Equal(r, c.expected) {
			t.Errorf("[%d] Unpad\n  Result  : %v\n  Expected: %v", i, r, c.expected)
		}
	}
}
