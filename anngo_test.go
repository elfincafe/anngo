package anngo

import "testing"

func TestGenerateIV(t *testing.T) {
	cases := []struct {
		size     int
		expected int
	}{
		{size: 16, expected: 16},
	}
	for i, c := range cases {
		iv, _ := GenerateIV(c.size)
		length := len(iv)
		if length != c.expected {
			t.Errorf(`[%d] Length Result: %d, Expected:%d`, i, length, c.expected)
		}

	}
}
