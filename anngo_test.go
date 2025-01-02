package anngo

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGenerateIV(t *testing.T) {
	cases := []struct {
		size     int
		expected int
	}{
		{size: 16, expected: 16},
	}
	for i, c := range cases {
		iv, _ := GenerateIV(c.size)
		length := len(iv)
		if length != c.expected {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, length, c.expected)
		}

	}
}

func TestCopyIV(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	cases := []struct {
		d        []byte
		s        []byte
		expected []byte
	}{
		{d: make([]byte, 16), s: b[:16], expected: b[:16]},
	}
	for i, c := range cases {
		copyIV(c.d, c.s)
		if !bytes.Equal(c.d, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, c.d, c.expected)
		}
	}
}
