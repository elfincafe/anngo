package padding

import (
	"testing"
)

func TestPaddingLength(t *testing.T) {
	cases := []struct {
		blockSize int
		length    int
		expected  int
	}{
		{Block128, 0, 0},
		{Block128, 15, 1},
		{Block128, 16, 0},
		{Block128, 17, 15},
		{Block192, 0, 0},
		{Block192, 23, 1},
		{Block192, 24, 0},
		{Block192, 25, 23},
		{Block256, 0, 0},
		{Block256, 31, 1},
		{Block256, 32, 0},
		{Block256, 33, 31},
	}
	for k, v := range cases {
		res := paddingLength(v.blockSize, v.length)
		if res != v.expected {
			t.Errorf(`[Case%d] Size: %d (%d)`, k, res, v.expected)
		}
	}
}

func TestIsValidBlockSize(t *testing.T) {
	cases := []struct {
		blockSize int
		expected  bool
	}{
		{Block128, true},
		{Block192, true},
		{Block256, true},
		{100, false},
		{0, false},
	}
	for k, v := range cases {
		res := isValidBlockSize(v.blockSize)
		if res != v.expected {
			t.Errorf(`[Case%d] Size: %v (%v)`, k, res, v.expected)
		}
	}
}
