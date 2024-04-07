package anngo

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewAnsiX923(t *testing.T) {
	cases := []struct {
		typ string
	}{
		{"*anngo.AnsiX923"},
	}
	for k, v := range cases {
		p := NewAnsiX923()
		typ := reflect.TypeOf(p).String()
		if typ != v.typ {
			t.Errorf(`[Case%d] %s (%s)`, k+1, typ, v.typ)
		}
	}
}

func TestAnsiX923Pad(t *testing.T) {
	b := []byte("~{,dkLRef($X&4s9jO[1Jr^H3vZ)+bxK#5Em-qwyDWA]@S.|I%_QUgh6uG!pNo20/itBTlPV8CMz7*F}cnaY")
	cases := []struct {
		buffer   []byte
		expected []byte
	}{
		{
			b[:16],
			b[:16],
		},
		{
			b[:32],
			b[:32],
		},
		{
			b[:44],
			append(append([]byte(""), b[:44]...), []byte{0x00, 0x00, 0x00, 0x04}...),
		},
		{
			b[10:51],
			append(append([]byte(""), b[10:51]...), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07}...),
		},
	}
	for k, v := range cases {
		p := NewAnsiX923()
		ret, _ := p.Pad(v.buffer)
		if !bytes.Equal(ret, v.expected) {
			t.Errorf("[Case%d] %v (%v)", k+1, ret, v.expected)
		}
	}
}

func TestAnsiX923Unpad(t *testing.T) {
	b := []byte("v4]e0@BZ*hDq+|s7nSVX-I6Oxl2.53CMuGUp1(8dPfgawc!m/&K_J)by$okLiA#zQHrj9,^N{F%E~}tW[TYR")
	cases := []struct {
		buffer   []byte
		expected []byte
	}{
		{
			b[:16],
			b[:16],
		},
		{
			b[:32],
			b[:32],
		},
		{
			b[:32],
			b[:32],
		},
	}
	for k, v := range cases {
		p := NewAnsiX923()
		ret, _ := p.Unpad(v.buffer)
		if !bytes.Equal(ret, v.expected) {
			t.Errorf("[Case%d] %v (%v)", k+1, ret, v.expected)
		}
	}
}

func TestAnsiX923Name(t *testing.T) {
	cases := []struct {
		name string
	}{
		{"ANSI X9.23"},
	}
	for k, v := range cases {
		p := NewAnsiX923()
		if p.Name() != v.name {
			t.Errorf("[Case%d] %s (%s)", k+1, p.Name(), v.name)
		}
	}
}
