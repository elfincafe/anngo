package anngo

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewIso10126(t *testing.T) {
	cases := []struct {
		typ string
	}{
		{"*anngo.ISO10126"},
	}
	for k, v := range cases {
		p := NewIso10126()
		typ := reflect.TypeOf(p).String()
		if typ != v.typ {
			t.Errorf(`[Case%d] %s (%s)`, k+1, typ, v.typ)
		}
	}
}

func TestIso10126Pad(t *testing.T) {
	b := []byte("_-phFHaoey3wWxqm&2+fB5!.rsZn^Mb[G]IcTU|{@1Jgl%Rd,u*~jXVtP8}#CA$Sz7iD(06KLNOYv/k9EQ)4")
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
			b[:31],
			append(append([]byte{}, b[:31]...), []byte{0x01}...),
		},
		{
			b[:30],
			append(append([]byte{}, b[:30]...), []byte{0x0a, 0x02}...),
		},
	}
	for k, v := range cases {
		p := NewIso10126()
		ret, _ := p.Pad(v.buffer)
		length := len(v.buffer)
		if !bytes.Equal(ret[:length], v.expected[:length]) || ret[length-1] != v.expected[length-1] {
			t.Errorf("[Case%d] %v (%v)", k+1, ret, v.expected)
		}
	}
}

func TestIso10126Unpad(t *testing.T) {
	b := []byte("4wrbA,ICf$hn]}vH{z[1p*^a-6k0iBsF+Zc~gxLtlY@eGQM&yqNPKU5TW)_%8o9jSV3m|J.XD2E(!/u#dRO7")
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
			append(append([]byte(""), b[:31]...), []byte{0x01}...),
			b[:31],
		},
		{
			append(append([]byte(""), b[:30]...), []byte{0xff, 0x02}...),
			b[:30],
		},
		{
			append(append([]byte(""), b[:40]...), []byte{0x00, 0xa1, 0x91, 0x5a, 0x22, 0xbe, 0xff, 0x08}...),
			b[:40],
		},
	}
	for k, v := range cases {
		p := NewIso10126()
		ret, _ := p.Unpad(v.buffer)
		if !bytes.Equal(ret, v.expected) {
			t.Errorf("[Case%d] %v (%v)", k+1, ret, v.expected)
		}
	}
}

func TestIso10126Name(t *testing.T) {
	cases := []struct {
		name string
	}{
		{"ISO 10126"},
	}
	for k, v := range cases {
		p := NewIso10126()
		if p.Name() != v.name {
			t.Errorf("[Case%d] %s (%s)", k+1, p.Name(), v.name)
		}
	}
}
