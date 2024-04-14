package anngo

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewPkcs7(t *testing.T) {
	cases := []struct {
		typ string
	}{
		{"anngo.PKCS7"},
	}
	for k, v := range cases {
		p := NewPkcs7()
		typ := reflect.TypeOf(p).String()
		if typ != v.typ {
			t.Errorf(`[Case%d] %s (%s)`, k+1, typ, v.typ)
		}
	}
}

func TestPkcs7Pad(t *testing.T) {
	b := []byte("7&!kcs9g^@|f*URr23nFHiL}v-~C{j_W[dla,1uXNA)qIy(txSJ#V0BT8KZweYhb46Qmz%EGpP.D5$/Mo]+O")
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
			append(append([]byte(""), b[:31]...), []byte{0x01}...),
		},
		{
			b[:33],
			append(append([]byte(""), b[:33]...), bytes.Repeat([]byte{0x0f}, 15)...),
		},
	}
	for k, v := range cases {
		p := NewPkcs7()
		ret, _ := p.Pad(v.buffer)
		if !bytes.Equal(ret, v.expected) {
			t.Errorf("[Case%d] %v (%v)", k+1, ret, v.expected)
		}
	}
}

func TestPkcs7Unpad(t *testing.T) {
	b := []byte("Owe5@F$0vV7/!}T-h#C%jucqMyYQH(42rBx6Zbi3,NzdPmt{L~Kp^]|WkGX.s+nlE_I[S*g&98RUAoD)a1fJ")
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
			append(append([]byte(""), b[:17]...), bytes.Repeat([]byte{0x0f}, 15)...),
			b[:17],
		},
	}
	for k, v := range cases {
		p := NewPkcs7()
		ret, _ := p.Unpad(v.buffer)
		if !bytes.Equal(ret, v.expected) {
			t.Errorf("[Case%d] %v (%v)", k+1, ret, v.expected)
		}
	}
}

func TestPkcs7Name(t *testing.T) {
	cases := []struct {
		name string
	}{
		{"PKCS7"},
	}
	for k, v := range cases {
		p := NewPkcs7()
		if p.Name() != v.name {
			t.Errorf("[Case%d] %s (%s)", k+1, p.Name(), v.name)
		}
	}
}
