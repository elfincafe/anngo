package anngo

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewZero(t *testing.T) {
	cases := []struct {
		typ string
	}{
		{"anngo.ZERO"},
	}
	for k, v := range cases {
		p := NewZero()
		typ := reflect.TypeOf(p).String()
		if typ != v.typ {
			t.Errorf(`[Case%d] %s (%s)`, k+1, typ, v.typ)
		}
	}
}

func TestZeroPad(t *testing.T) {
	b := []byte("cM7U#fNe4ug9q1Y*pzn@tS3Q,yA$L%V~Or{Gv5Z2.d]slKWI^j0X&!8km)B_FDo-C/waHbhRPTx|E}+J(6[i")
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
			append(append([]byte(""), b[:31]...), []byte{0x00}...),
		},
		{
			b[:33],
			append(append([]byte(""), b[:33]...), bytes.Repeat([]byte{0x00}, 15)...),
		},
	}
	for k, v := range cases {
		p := NewZero()
		b, _ := p.Pad(v.buffer)
		if !bytes.Equal(b, v.expected) {
			t.Errorf(`[Case%d] %v (%v)`, k+1, b, v.expected)
		}
	}
}

func TestZeroUnpad(t *testing.T) {
	b := []byte("DK-(n#t8/EXN7.dqF5,mc1@h{CUekbMI*2iB^ur!fw%}vJH)46+y~[Q$_ZRVTS9]Y0jGzpxW3s&Oa|AoglPL")
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
			append(append([]byte(""), b[:31]...), []byte{0x00}...),
			b[:31],
		},
		{
			append(append([]byte(""), b[:17]...), bytes.Repeat([]byte{0x00}, 15)...),
			b[:17],
		},
		{
			append(append([]byte(""), b[:16]...), bytes.Repeat([]byte{0x00}, 16)...),
			append(append([]byte(""), b[:16]...), bytes.Repeat([]byte{0x00}, 1)...),
		},
	}
	for k, v := range cases {
		p := NewZero()
		res, _ := p.Unpad(v.buffer)
		if !bytes.Equal(res, v.expected) {
			t.Errorf("[Case%d] %v (%v)", k+1, res, v.expected)
		}
	}
}

func TestZeroName(t *testing.T) {
	cases := []struct {
		name string
	}{
		{"ZERO"},
	}
	for k, v := range cases {
		p := NewZero()
		if p.Name() != v.name {
			t.Errorf(`[Case%d] %s (%s)`, k+1, p.Name(), v.name)
		}
	}
}
