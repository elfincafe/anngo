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
		{128, 0, 0},
		{128, 15, 1},
		{128, 16, 0},
		{128, 17, 15},
		{192, 0, 0},
		{192, 23, 1},
		{192, 24, 0},
		{192, 25, 23},
		{256, 0, 0},
		{256, 31, 1},
		{256, 32, 0},
		{256, 33, 31},
	}
	for k, v := range cases {
		res := paddingLength(v.blockSize, v.length)
		if res != v.expected {
			t.Errorf(`[Case%d] Size: %d (%d)`, k, res, v.expected)
		}
	}
}
