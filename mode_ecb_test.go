package anngo

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestNewECB(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	m := NewECB(b[:16], NewPkcs7())
	v := reflect.TypeOf(m)
	if v.Kind() != reflect.Pointer {
		t.Errorf("Mode: %v, Expected: %v", v.Kind(), reflect.Pointer)
	} else if v.Elem().Name() != "ECB" {
		t.Errorf("Mode Name: %v, Expected: %v", v.Name(), "ECB")
	}
}

func TestECBEncrypt(t *testing.T) {
	// Case
	cases := []struct {
		key      []byte
		data     []byte
		padder   PadderInterface
		expected []byte
	}{
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmn"),
			padder:   NewZero(),
			expected: []byte{199, 113, 79, 73, 58, 4, 204, 135, 10, 206, 188, 92, 32, 40, 98, 29},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmno"),
			padder:   NewZero(),
			expected: []byte{48, 242, 176, 181, 85, 22, 255, 90, 222, 190, 116, 226, 183, 221, 114, 130},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnop"),
			padder:   NewZero(),
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   NewZero(),
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 127, 190, 79, 20, 6, 186, 186, 103, 88, 127, 236, 153, 65, 17, 246, 205},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   NewZero(),
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 211, 249, 163, 244, 147, 25, 4, 177, 118, 6, 115, 70, 74, 100, 11, 208},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmn"),
			padder:   NewPkcs7(),
			expected: []byte{55, 21, 77, 54, 24, 109, 250, 166, 56, 152, 91, 46, 107, 97, 56, 134},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmno"),
			padder:   NewPkcs7(),
			expected: []byte{205, 215, 47, 196, 28, 56, 247, 118, 68, 155, 191, 77, 166, 186, 198, 250},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnop"),
			padder:   NewPkcs7(),
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   NewPkcs7(),
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 199, 82, 84, 255, 34, 17, 34, 147, 205, 245, 192, 29, 244, 124, 68, 51},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   NewPkcs7(),
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 75, 163, 126, 99, 191, 217, 232, 162, 241, 121, 251, 177, 126, 74, 145, 220},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmn"),
			padder:   NewAnsiX923(),
			expected: []byte{238, 29, 43, 26, 117, 109, 105, 9, 180, 105, 203, 171, 104, 235, 183, 82},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmno"),
			padder:   NewAnsiX923(),
			expected: []byte{205, 215, 47, 196, 28, 56, 247, 118, 68, 155, 191, 77, 166, 186, 198, 250},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnop"),
			padder:   NewAnsiX923(),
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   NewAnsiX923(),
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 52, 223, 69, 58, 172, 38, 192, 74, 146, 67, 102, 47, 198, 99, 117, 100},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   NewAnsiX923(),
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 204, 194, 38, 117, 173, 28, 94, 231, 246, 167, 239, 8, 75, 91, 124, 130},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmn"),
			padder:   NewZero(),
			expected: []byte{153, 190, 237, 2, 111, 164, 236, 104, 104, 4, 40, 126, 28, 215, 251, 244},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmno"),
			padder:   NewZero(),
			expected: []byte{14, 98, 184, 175, 9, 234, 34, 54, 252, 156, 3, 93, 93, 71, 70, 255},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnop"),
			padder:   NewZero(),
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   NewZero(),
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 3, 250, 163, 66, 137, 97, 178, 177, 244, 21, 194, 88, 162, 100, 46, 122},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   NewZero(),
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 31, 87, 171, 23, 91, 136, 216, 200, 96, 49, 248, 197, 113, 161, 226, 191},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmn"),
			padder:   NewPkcs7(),
			expected: []byte{204, 148, 233, 40, 238, 195, 248, 21, 162, 8, 190, 215, 182, 16, 108, 0},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmno"),
			padder:   NewPkcs7(),
			expected: []byte{34, 206, 80, 92, 182, 165, 35, 191, 10, 224, 158, 170, 168, 52, 189, 161},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnop"),
			padder:   NewPkcs7(),
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   NewPkcs7(),
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 60, 170, 41, 177, 133, 79, 181, 24, 155, 44, 59, 226, 97, 120, 164, 136},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   NewPkcs7(),
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 223, 113, 2, 50, 212, 171, 241, 193, 192, 14, 10, 213, 214, 110, 201, 5},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmn"),
			padder:   NewAnsiX923(),
			expected: []byte{200, 116, 77, 188, 227, 83, 254, 239, 35, 222, 151, 98, 254, 132, 63, 9},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmno"),
			padder:   NewAnsiX923(),
			expected: []byte{34, 206, 80, 92, 182, 165, 35, 191, 10, 224, 158, 170, 168, 52, 189, 161},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnop"),
			padder:   NewAnsiX923(),
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   NewAnsiX923(),
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 222, 40, 224, 165, 70, 37, 112, 6, 39, 174, 31, 26, 127, 40, 49, 246},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   NewAnsiX923(),
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 13, 161, 125, 73, 179, 158, 186, 46, 177, 199, 195, 74, 79, 56, 189, 163},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmn"),
			padder:   NewZero(),
			expected: []byte{221, 147, 143, 43, 181, 108, 149, 221, 101, 51, 23, 116, 76, 122, 225, 99},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmno"),
			padder:   NewZero(),
			expected: []byte{91, 190, 230, 253, 230, 119, 55, 106, 2, 62, 124, 65, 44, 157, 170, 91},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnop"),
			padder:   NewZero(),
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   NewZero(),
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 1, 141, 206, 8, 15, 182, 46, 67, 44, 120, 138, 71, 178, 207, 1, 226},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   NewZero(),
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 154, 231, 56, 153, 225, 107, 213, 130, 191, 188, 3, 104, 75, 142, 125, 151},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmn"),
			padder:   NewPkcs7(),
			expected: []byte{125, 143, 121, 9, 127, 221, 251, 238, 232, 218, 225, 174, 152, 88, 63, 196},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmno"),
			padder:   NewPkcs7(),
			expected: []byte{185, 120, 176, 119, 188, 33, 56, 139, 180, 61, 193, 193, 140, 156, 83, 117},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnop"),
			padder:   NewPkcs7(),
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   NewPkcs7(),
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 142, 222, 157, 213, 110, 182, 24, 122, 107, 57, 185, 144, 211, 163, 120, 33},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   NewPkcs7(),
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 252, 18, 148, 68, 155, 1, 169, 179, 205, 164, 133, 86, 121, 70, 34, 236},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmn"),
			padder:   NewAnsiX923(),
			expected: []byte{141, 103, 78, 66, 218, 130, 83, 62, 203, 25, 178, 58, 13, 12, 22, 213},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmno"),
			padder:   NewAnsiX923(),
			expected: []byte{185, 120, 176, 119, 188, 33, 56, 139, 180, 61, 193, 193, 140, 156, 83, 117},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnop"),
			padder:   NewAnsiX923(),
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   NewAnsiX923(),
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 231, 85, 177, 1, 69, 253, 47, 38, 93, 178, 187, 133, 218, 155, 46, 111},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   NewAnsiX923(),
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 155, 157, 107, 85, 209, 89, 135, 151, 183, 184, 162, 69, 249, 118, 33, 213},
		},
	}
	// Test
	for i, c := range cases {
		m := NewECB(c.key, c.padder)
		ret, _ := m.Encrypt(c.data)
		if !bytes.Equal(ret, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, ret, c.expected)
		}
	}
}

func TestECBDecrypt(t *testing.T) {
	// Case
	cases := []struct {
		key      []byte
		data     []byte
		padder   PadderInterface
		expected []byte
	}{
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{199, 113, 79, 73, 58, 4, 204, 135, 10, 206, 188, 92, 32, 40, 98, 29},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{48, 242, 176, 181, 85, 22, 255, 90, 222, 190, 116, 226, 183, 221, 114, 130},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 127, 190, 79, 20, 6, 186, 186, 103, 88, 127, 236, 153, 65, 17, 246, 205},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 211, 249, 163, 244, 147, 25, 4, 177, 118, 6, 115, 70, 74, 100, 11, 208},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{55, 21, 77, 54, 24, 109, 250, 166, 56, 152, 91, 46, 107, 97, 56, 134},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{205, 215, 47, 196, 28, 56, 247, 118, 68, 155, 191, 77, 166, 186, 198, 250},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 199, 82, 84, 255, 34, 17, 34, 147, 205, 245, 192, 29, 244, 124, 68, 51},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 75, 163, 126, 99, 191, 217, 232, 162, 241, 121, 251, 177, 126, 74, 145, 220},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{238, 29, 43, 26, 117, 109, 105, 9, 180, 105, 203, 171, 104, 235, 183, 82},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{205, 215, 47, 196, 28, 56, 247, 118, 68, 155, 191, 77, 166, 186, 198, 250},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 52, 223, 69, 58, 172, 38, 192, 74, 146, 67, 102, 47, 198, 99, 117, 100},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 204, 194, 38, 117, 173, 28, 94, 231, 246, 167, 239, 8, 75, 91, 124, 130},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{153, 190, 237, 2, 111, 164, 236, 104, 104, 4, 40, 126, 28, 215, 251, 244},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{14, 98, 184, 175, 9, 234, 34, 54, 252, 156, 3, 93, 93, 71, 70, 255},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 3, 250, 163, 66, 137, 97, 178, 177, 244, 21, 194, 88, 162, 100, 46, 122},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 31, 87, 171, 23, 91, 136, 216, 200, 96, 49, 248, 197, 113, 161, 226, 191},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{204, 148, 233, 40, 238, 195, 248, 21, 162, 8, 190, 215, 182, 16, 108, 0},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{34, 206, 80, 92, 182, 165, 35, 191, 10, 224, 158, 170, 168, 52, 189, 161},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 60, 170, 41, 177, 133, 79, 181, 24, 155, 44, 59, 226, 97, 120, 164, 136},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 223, 113, 2, 50, 212, 171, 241, 193, 192, 14, 10, 213, 214, 110, 201, 5},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{200, 116, 77, 188, 227, 83, 254, 239, 35, 222, 151, 98, 254, 132, 63, 9},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{34, 206, 80, 92, 182, 165, 35, 191, 10, 224, 158, 170, 168, 52, 189, 161},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 222, 40, 224, 165, 70, 37, 112, 6, 39, 174, 31, 26, 127, 40, 49, 246},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 13, 161, 125, 73, 179, 158, 186, 46, 177, 199, 195, 74, 79, 56, 189, 163},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{221, 147, 143, 43, 181, 108, 149, 221, 101, 51, 23, 116, 76, 122, 225, 99},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{91, 190, 230, 253, 230, 119, 55, 106, 2, 62, 124, 65, 44, 157, 170, 91},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 1, 141, 206, 8, 15, 182, 46, 67, 44, 120, 138, 71, 178, 207, 1, 226},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 154, 231, 56, 153, 225, 107, 213, 130, 191, 188, 3, 104, 75, 142, 125, 151},
			padder:   NewZero(),
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{125, 143, 121, 9, 127, 221, 251, 238, 232, 218, 225, 174, 152, 88, 63, 196},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{185, 120, 176, 119, 188, 33, 56, 139, 180, 61, 193, 193, 140, 156, 83, 117},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 142, 222, 157, 213, 110, 182, 24, 122, 107, 57, 185, 144, 211, 163, 120, 33},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 252, 18, 148, 68, 155, 1, 169, 179, 205, 164, 133, 86, 121, 70, 34, 236},
			padder:   NewPkcs7(),
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{141, 103, 78, 66, 218, 130, 83, 62, 203, 25, 178, 58, 13, 12, 22, 213},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{185, 120, 176, 119, 188, 33, 56, 139, 180, 61, 193, 193, 140, 156, 83, 117},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 231, 85, 177, 1, 69, 253, 47, 38, 93, 178, 187, 133, 218, 155, 46, 111},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 155, 157, 107, 85, 209, 89, 135, 151, 183, 184, 162, 69, 249, 118, 33, 213},
			padder:   NewAnsiX923(),
			expected: []byte("abcdefghijklmnopqr"),
		},
	}
	// Test
	for i, c := range cases {
		m := NewECB(c.key, c.padder)
		ret, _ := m.Decrypt(c.data)
		if !bytes.Equal(ret, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, ret, c.expected)
		}
	}
}
