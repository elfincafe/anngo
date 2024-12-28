package anngo

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestNewCTR(t *testing.T) {

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
	aes := NewCTR(b[16:32])
	for i, c := range cases {
		aes.SetIV(c.iv)
		if !bytes.Equal(aes.iv, c.iv) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, aes.iv, c.expected)
		}
	}
}
