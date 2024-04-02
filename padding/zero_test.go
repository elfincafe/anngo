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
	b := []byte("K-*j,%Zosz_wq^{)fvL}1iYS0GJOBaIr@WU|heHl!2PX9mkTp7(y+~Q/]6&5NxgtFR[EM$.bA3Du8nd4cC#V")
	cases := []struct {
		blockSize int
		buffer    []byte
		expected  []byte
	}{
		{
			128,
			b[0:16],
			b[0:16],
		},
		{
			128,
			b[0:32],
			b[0:32],
		},
		{
			128,
			b[30:47],
			append(b[30:47], bytes.Repeat([]byte{0x00}, 15)...),
		},
		{
			128,
			b[50:65],
			append(b[50:65], byte(0x00)),
		},
		{
			192,
			[]byte("0123456789abcdefghijklmn"),
			[]byte("0123456789abcdefghijklmn"),
		},
		{
			192,
			[]byte("0123456789abcdefghijklmn0123456789abcdefghijklmn"),
			[]byte("0123456789abcdefghijklmn0123456789abcdefghijklmn"),
		},
		{
			192,
			[]byte("0123456789abcdefghijklmn0"),
			append([]byte("0123456789abcdefghijklmn0"), bytes.Repeat([]byte{0x00}, 23)...),
		},
		{
			192,
			[]byte("0123456789abcdefghijklmn0123456789abcdefghijklm"),
			append([]byte("0123456789abcdefghijklmn0123456789abcdefghijklm"), byte(0x00)),
		},
		{
			256,
			[]byte("0123456789abcdefghijklmnopqrstuv"),
			[]byte("0123456789abcdefghijklmnopqrstuv"),
		},
		{
			256,
			[]byte("0123456789abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrstuv"),
			[]byte("0123456789abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrstuv"),
		},
		{
			256,
			[]byte("0123456789abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrstuvw"),
			append([]byte("0123456789abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrstuvw"), bytes.Repeat([]byte{0x00}, 31)...),
		},
		{
			256,
			[]byte("0123456789abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrstu"),
			append([]byte("0123456789abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrstu"), byte(0x00)),
		},
	}
	for k, v := range cases {
		p := NewZero(v.buffer)
		b, _ := p.Pad(v.blockSize)
		if !bytes.Equal(b, v.expected) {
			t.Errorf(`[Case%d] %v (%v)`, k, b, v.expected)
		}
	}
}

func TestZeroUnpad(t *testing.T) {
	b := []byte(",}[#P1y*]k.~B3nC5DbM(fWGF|6S)zOU^_wJ2A%pmoNv&EhsqZV@u{Q0-TR$Ix87i/HXr+g!cKa4ldYLt9je")
	cases := []struct {
		bit    int
		buf    []byte
		expect []byte
	}{
		{
			128,
			bytes.Repeat([]byte("0123456789abcdef"), 1),
			bytes.Repeat([]byte("0123456789abcdef"), 1),
		},
		{
			128,
			bytes.Repeat([]byte("0123456789abcdef"), 2),
			bytes.Repeat([]byte("0123456789abcdef"), 2),
		},
		{
			128,
			append([]byte("0123456789abcdef0123456789abcd"), byte(0x00), byte(0x00)),
			[]byte("0123456789abcdef0123456789abcd"),
		},
		{
			128,
			append([]byte("0123456789abcdef0123456789abcde"), byte(0x00)),
			[]byte("0123456789abcdef0123456789abcde"),
		},
		{
			192,
			bytes.Repeat([]byte("0123456789abcdefghijklmn"), 1),
			bytes.Repeat([]byte("0123456789abcdefghijklmn"), 1),
		},
		{
			192,
			bytes.Repeat([]byte("0123456789abcdefghijklmn"), 2),
			bytes.Repeat([]byte("0123456789abcdefghijklmn"), 2),
		},
		{
			192,
			append([]byte("0123456789abcdefghijklmn0123456789abcdefghijkl"), byte(0x00), byte(0x00)),
			[]byte("0123456789abcdefghijklmn0123456789abcdefghijkl"),
		},
		{
			192,
			append([]byte("0123456789abcdefghijklmn0123456789abcdefghijklm"), byte(0x00)),
			[]byte("0123456789abcdefghijklmn0123456789abcdefghijklm"),
		},
		{
			256,
			bytes.Repeat([]byte("0123456789abcdefghijklmnopqrstuv"), 1),
			bytes.Repeat([]byte("0123456789abcdefghijklmnopqrstuv"), 1),
		},
		{
			256,
			bytes.Repeat([]byte("0123456789abcdefghijklmnopqrstuv"), 2),
			bytes.Repeat([]byte("0123456789abcdefghijklmnopqrstuv"), 2),
		},
		{
			256,
			append([]byte("0123456789abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrst"), byte(0x00), byte(0x00)),
			[]byte("0123456789abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrst"),
		},
		{
			256,
			append([]byte("0123456789abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrstu"), byte(0x00)),
			[]byte("0123456789abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrstu"),
		},
	}
	for k, v := range cases {
		p := NewZero(v.buf)
		res, _ := p.Unpad(v.bit)
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
