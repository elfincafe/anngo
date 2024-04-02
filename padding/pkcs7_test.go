package padding

import (
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
	b := []byte("{[N+oM/hujgQ_eVD}i3Y#%a0H|q1z$8].W52OJ~mP@(&6)IByC!-ZFrXvAUnGbTLkl^4cs*dwt7SE9,RfpxK")
}

func TestPkcs7Unpad(t *testing.T) {
	b := []byte("sm_@BT4&ap^iJ)-bAHQLCZFc|PrS(nRG/Vg,!t375.]NXf${1[}hIe2l9ydE#+vzk0WKo8j~UOw%MYDxq6*u")
}
