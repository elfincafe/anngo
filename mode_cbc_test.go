package anngo

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"strings"
	"testing"
)

func TestNewCBC(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	m := NewCBC(b[:16], NewPkcs7())
	v := reflect.TypeOf(m)
	if v.Kind() != reflect.Struct {
		t.Errorf("Padding Type: %v, Expected: %v", v.Kind(), reflect.Struct)
	} else if v.Name() != "ANSIX923" {
		t.Errorf("Padding Name: %v, Expected: %v", v.Name(), "ANSIX923")
	}
}

func TestCBCEncrypt(t *testing.T) {
	// Case
	cases := []struct {
		s        []byte
		p        PaddingInterface
		expected []byte
	}{
		{
			s:        []byte("abcdefghijklmnop"),
			p:        NewPkcs7(),
			expected: []byte{},
		},
	}
	// Test
	key := []byte("0123456789abcdef")
	iv := []byte("alouepc95malj23l")
	for i, c := range cases {
		m := NewCBC(key, c.p)
		m.SetIV(iv)
		r, _ := m.Encrypt(c.s)
		if !bytes.Equal(r, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, r, c.expected)
		}
	}
}

func TestCBCEncryptError(t *testing.T) {
	// Case
	cases := []struct {
		s   []byte
		err string
	}{
		{s: []byte("a"), err: ""},
	}
	// Test
	passwd := []byte("0123456789abcdefg")
	m := NewCBC(passwd, NewPkcs7())
	for i, c := range cases {
		_, err := m.Encrypt(c.s)
		if !strings.Contains(err.Error(), c.err) {
			t.Errorf("\n<Case%d>\nError:   %v\nExpected: %v\n", i, err.Error(), c.err)
		}
	}
}

func TestCBCDecrypt(t *testing.T) {}

func TestCBCSetIV(t *testing.T) {
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
	aes := NewCBC(b[16:32], NewPkcs7())
	for i, c := range cases {
		aes.SetIV(c.iv)
		if !bytes.Equal(aes.iv, c.iv) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, aes.iv, c.expected)
		}
	}
}
