package anngo

import (
	"testing"
)

func TestGenerate(t *testing.T) {
	cases := []struct {
		blockSize int
	}{
		{AES128},
		{AES192},
		{AES256},
		{123},
	}
	for k, v := range cases {
		b := Generate(v.blockSize)
		if len(b) != v.blockSize {
			t.Errorf(`[Case%d] %d (%d)`, k, len(b), v.blockSize)
		}
	}
}
