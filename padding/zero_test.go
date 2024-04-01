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
			[]byte("0123456789abcdef"),
			[]byte("0123456789abcdef"),
		},
		{
			128,
			[]byte("0123456789abcdef0123456789abcdef"),
			[]byte("0123456789abcdef0123456789abcdef"),
		},
		{
			128,
			[]byte("0123456789abcdefg"),
			append([]byte("0123456789abcdefg"), bytes.Repeat([]byte{0x00}, 15)...),
		},
		{
			128,
			[]byte("0123456789abcde"),
			append([]byte("0123456789abcde"), byte(0x00)),
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
