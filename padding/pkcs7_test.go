package padding

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewPkcs7(t *testing.T) {
	cases := []struct {
		typ string
	}{
		{"*padding.PKCS7"},
	}
	for k, v := range cases {
		p := NewPkcs7([]byte{})
		typ := reflect.TypeOf(p).String()
		if typ != v.typ {
			t.Errorf(`[Case%d] %s (%s)`, k, typ, v.typ)
		}
	}
}

func TestPkcs7Pad(t *testing.T) {
	b := []byte("7&!kcs9g^@|f*URr23nFHiL}v-~C{j_W[dla,1uXNA)qIy(txSJ#V0BT8KZweYhb46Qmz%EGpP.D5$/Mo]+O")
	cases := []struct {
		buffer []byte
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
	}
	for k, v := range cases {
		p := NewPkcs7(v.buffer)
		ret, _ := p.Pad()
		if !bytes.Equal(ret, v.expect) {
			t.Errorf("[Case%d] %v (%v)", k, ret, v.expect)
		}
	}
}

func TestPkcs7Unpad(t *testing.T) {
	b := []byte("Owe5@F$0vV7/!}T-h#C%jucqMyYQH(42rBx6Zbi3,NzdPmt{L~Kp^]|WkGX.s+nlE_I[S*g&98RUAoD)a1fJ")
	cases := []struct {
		buffer []byte
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
	}
	for k, v := range cases {
		p := NewPkcs7(v.buffer)
		ret, _ := p.Unpad()
		if !bytes.Equal(ret, v.expect) {
			t.Errorf("[Case%d] %v (%v)", k, ret, v.expect)
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
		p := NewPkcs7([]byte(""))
		if p.Name() != v.name {
			t.Errorf("[Case%d] %s (%s)", k, p.Name(), v.name)
		}
	}
}
