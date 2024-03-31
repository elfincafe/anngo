package padding

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestNewZero(t *testing.T) {
	cases := []struct {
		typ string
	}{
		{"*padding.Zero"},
	}
	for k, v := range cases {
		p := NewZero([]byte{})
		typ := reflect.TypeOf(p).String()
		fmt.Println(typ)
		if typ != v.typ {
			t.Errorf(`[Case%d] %s (%s)`, k, typ, v.typ)
		}
	}
}

func TestZeroPad(t *testing.T) {
	cases := []struct {
		blockSize int
		buffer    []byte
		expected  []byte
	}{
		{
			128,
			[]byte("0123456789abcde"),
			append([]byte("0123456789abcde"), 0x00),
		},
		{
			128,
			[]byte("0123456789abcdef"),
			[]byte("0123456789abcdef"),
		},
		{
			128,
			[]byte("0123456789abcdefg"),
			append([]byte("0123456789abcdefg"), bytes.Repeat([]byte{0x00}, 15)...),
		},
	}
	for k, v := range cases {
		p := NewZero(v.buffer)
		b, _ := p.Pad(v.blockSize / 16)
		if !bytes.Equal(b, v.expected) {
			t.Errorf(`[Case%d] %v (%v)`, k, b)
		}
	}
}

func TestZeroUnpad(t *testing.T) {

}

func TestZeroName(t *testing.T) {
	cases := []struct {
		name string
	}{
		{"Zero"},
	}
	for k, v := range cases {
		p := NewZero([]byte{})
		name := p.Name()
		if name == v.name {
			t.Errorf(`[Case%d] %s (%s)`, k, name, v.name)
		}
	}
}
