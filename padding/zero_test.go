package padding

import (
	"bytes"
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
		if typ != v.typ {
			t.Errorf(`[Case%d] %s (%s)`, k, typ, v.typ)
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
			b[:62],
			append(b[:62], bytes.Repeat([]byte{0x00}, 2)...),
		},
		{
			b[:79],
			append(b[:63], bytes.Repeat([]byte{0x00}, 1)...),
		},
	}
	for k, v := range cases {
		p := NewZero(v.buffer)
		b, _ := p.Pad()
		if !bytes.Equal(b, v.expected) {
			t.Errorf(`[Case%d] %v (%v)`, k, b, v.expected)
		}
	}
}

func TestZeroUnpad(t *testing.T) {
	b := []byte("DK-(n#t8/EXN7.dqF5,mc1@h{CUekbMI*2iB^ur!fw%}vJH)46+y~[Q$_ZRVTS9]Y0jGzpxW3s&Oa|AoglPL")
	cases := []struct {
		buf    []byte
		expect []byte
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
			append(b[10:60], byte(0x00), byte(0x00)),
			b[30:60],
		},
		{
			append(b[40:73], byte(0x00)),
			b[40:73],
		},
	}
	for k, v := range cases {
		p := NewZero(v.buf)
		res, _ := p.Unpad()
		if !bytes.Equal(res, v.expect) {
			t.Errorf("[Case%d] %v", k, res)
		}
	}
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
