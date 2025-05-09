package anngo

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestNewCBC(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	m := NewCBC(b[:16])
	v := reflect.TypeOf(m)
	if v.Kind() != reflect.Pointer {
		t.Errorf("Mode: %v, Expected: %v", v.Kind(), reflect.Pointer)
	} else if v.Elem().Name() != "CBC" {
		t.Errorf("Mode Name: %v, Expected: %v", v.Name(), "CBC")
	}
}

func TestCBCPkcs7(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	m := NewCBC(b[:16])
	m.padder = zeroPadding{}
	typ := reflect.TypeOf(m.padder).Name()
	if typ != "zeroPadding" {
		t.Errorf("not ready yet")
	}
	m.Pkcs7()
	typ = reflect.TypeOf(m.padder).Name()
	if typ != "pkcs7Padding" {
		t.Errorf("Result: %s, Expected: %s", typ, "pkcs7Padding")
	}
}

func TestCBCZeroPadding(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	m := NewCBC(b[:16])
	typ := reflect.TypeOf(m.padder).Name()
	if typ != "pkcs7Padding" {
		t.Errorf("not ready yet")
	}
	m.ZeroPadding()
	typ = reflect.TypeOf(m.padder).Name()
	if typ != "zeroPadding" {
		t.Errorf("Result: %s, Expected: %s", typ, "zeroPadding")
	}
}

func TestCBCAnsiX923(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	m := NewCBC(b[:16])
	typ := reflect.TypeOf(m.padder).Name()
	if typ != "pkcs7Padding" {
		t.Errorf("not ready yet")
	}
	m.AnsiX923()
	typ = reflect.TypeOf(m.padder).Name()
	if typ != "ansiX923Padding" {
		t.Errorf("Result: %s, Expected: %s", typ, "ansiX923Padding")
	}
}

func TestCBCIso10126(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	m := NewCBC(b[:16])
	typ := reflect.TypeOf(m.padder).Name()
	if typ != "pkcs7Padding" {
		t.Errorf("not ready yet")
	}
	m.Iso10126()
	typ = reflect.TypeOf(m.padder).Name()
	if typ != "iso10126Padding" {
		t.Errorf("Result: %s, Expected: %s", typ, "iso10126Padding")
	}
}

func TestCBCEncrypt(t *testing.T) {
	// Case
	cases := []struct {
		key      []byte
		data     []byte
		iv       []byte
		padder   padderInterface
		expected []byte
	}{
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{76, 212, 135, 60, 37, 88, 123, 16, 16, 134, 234, 206, 230, 151, 113, 143},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{185, 162, 129, 177, 213, 80, 108, 81, 158, 165, 81, 13, 240, 60, 94, 205},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 185, 225, 174, 44, 65, 186, 67, 197, 191, 9, 145, 158, 80, 182, 103, 166},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 193, 17, 27, 206, 252, 17, 93, 189, 13, 185, 222, 184, 1, 176, 38, 129},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 63, 201, 83, 162, 71, 97, 163, 234, 31, 121, 161, 241, 184, 151, 129, 55},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{171, 49, 251, 54, 223, 25, 248, 196, 44, 171, 170, 46, 241, 244, 107, 46},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{98, 186, 15, 169, 134, 220, 27, 98, 104, 138, 93, 190, 113, 162, 29, 87},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 153, 165, 56, 93, 33, 142, 163, 89, 162, 124, 212, 142, 61, 107, 152, 51},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 62, 188, 168, 105, 205, 43, 116, 18, 237, 100, 232, 181, 2, 157, 242, 214},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 90, 25, 211, 50, 31, 54, 146, 46, 151, 172, 134, 124, 38, 24, 36, 63},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{151, 103, 232, 162, 126, 99, 216, 134, 36, 9, 231, 244, 53, 48, 88, 164},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{98, 186, 15, 169, 134, 220, 27, 98, 104, 138, 93, 190, 113, 162, 29, 87},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 163, 194, 41, 127, 235, 32, 213, 154, 152, 246, 224, 156, 176, 255, 214, 174},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 0, 153, 183, 154, 182, 105, 144, 54, 118, 215, 12, 248, 26, 215, 60, 126},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 135, 87, 66, 103, 230, 217, 143, 79, 143, 239, 56, 194, 218, 11, 13, 184},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{125, 26, 71, 57, 17, 197, 47, 94, 34, 145, 8, 158, 212, 254, 242, 36},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{238, 164, 206, 148, 80, 140, 80, 109, 47, 87, 105, 217, 27, 24, 185, 53},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 34, 202, 124, 137, 36, 34, 92, 149, 92, 129, 255, 83, 148, 124, 106, 20},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 220, 247, 15, 132, 252, 148, 60, 228, 114, 187, 227, 63, 131, 157, 169, 163},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 156, 137, 213, 228, 163, 160, 157, 194, 10, 190, 109, 117, 12, 156, 22, 5},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{87, 227, 63, 59, 44, 13, 2, 27, 176, 124, 204, 82, 220, 57, 168, 58},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{51, 133, 183, 176, 188, 0, 51, 238, 129, 102, 85, 26, 101, 197, 255, 152},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 117, 2, 232, 214, 129, 23, 249, 149, 50, 55, 84, 188, 175, 9, 194, 131},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 203, 106, 115, 199, 114, 140, 215, 96, 69, 157, 42, 206, 169, 161, 158, 6},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 173, 7, 28, 95, 98, 30, 208, 108, 12, 175, 140, 195, 214, 150, 95, 245},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{94, 183, 32, 153, 219, 203, 220, 200, 189, 141, 161, 86, 213, 112, 151, 248},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{51, 133, 183, 176, 188, 0, 51, 238, 129, 102, 85, 26, 101, 197, 255, 152},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 137, 172, 203, 184, 177, 46, 73, 228, 7, 68, 199, 11, 28, 211, 237, 195},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 148, 15, 229, 4, 139, 137, 147, 127, 184, 36, 55, 29, 26, 98, 61, 112},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 154, 219, 187, 153, 36, 214, 125, 67, 58, 155, 175, 225, 103, 109, 255, 19},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{49, 30, 215, 241, 103, 74, 106, 14, 203, 180, 184, 116, 67, 234, 15, 242},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{8, 236, 2, 85, 82, 71, 73, 24, 109, 238, 59, 157, 234, 133, 22, 73},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 55, 6, 103, 181, 75, 146, 59, 61, 181, 186, 204, 148, 242, 78, 1, 145},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 140, 98, 150, 106, 163, 205, 174, 224, 56, 249, 42, 100, 142, 16, 245, 127},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 46, 188, 134, 240, 37, 115, 34, 70, 6, 5, 238, 187, 37, 215, 111, 16},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{18, 234, 184, 199, 61, 243, 153, 158, 34, 142, 125, 207, 169, 8, 243, 151},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{205, 165, 182, 49, 227, 252, 104, 57, 57, 66, 144, 220, 126, 20, 78, 221},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 220, 70, 178, 48, 196, 89, 166, 138, 182, 29, 117, 237, 234, 122, 190, 114},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 13, 201, 205, 170, 164, 185, 192, 255, 92, 118, 19, 5, 197, 34, 113, 21},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 17, 102, 224, 72, 125, 246, 10, 131, 36, 118, 104, 156, 210, 232, 181, 190},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{48, 108, 154, 74, 181, 18, 10, 139, 81, 17, 214, 13, 155, 206, 249, 217},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{205, 165, 182, 49, 227, 252, 104, 57, 57, 66, 144, 220, 126, 20, 78, 221},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 205, 231, 191, 145, 172, 163, 217, 224, 239, 133, 115, 165, 250, 16, 28, 243},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 149, 148, 54, 64, 111, 28, 241, 108, 126, 255, 41, 235, 42, 120, 234, 56},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 235, 238, 150, 255, 118, 173, 205, 233, 2, 155, 4, 21, 53, 110, 150, 144},
		},
	}
	// Test
	for i, c := range cases {
		m := NewCBC(c.key)
		m.padder = c.padder
		copy(m.iv, c.iv)
		ret, _ := m.Encrypt(c.data)
		if !bytes.Equal(ret, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, ret, c.expected)
		}
	}
}

func TestCBCDecrypt(t *testing.T) {
	// Case
	cases := []struct {
		key      []byte
		data     []byte
		iv       []byte
		padder   padderInterface
		expected []byte
	}{
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{76, 212, 135, 60, 37, 88, 123, 16, 16, 134, 234, 206, 230, 151, 113, 143},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{185, 162, 129, 177, 213, 80, 108, 81, 158, 165, 81, 13, 240, 60, 94, 205},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 185, 225, 174, 44, 65, 186, 67, 197, 191, 9, 145, 158, 80, 182, 103, 166},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 193, 17, 27, 206, 252, 17, 93, 189, 13, 185, 222, 184, 1, 176, 38, 129},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 63, 201, 83, 162, 71, 97, 163, 234, 31, 121, 161, 241, 184, 151, 129, 55},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{171, 49, 251, 54, 223, 25, 248, 196, 44, 171, 170, 46, 241, 244, 107, 46},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{98, 186, 15, 169, 134, 220, 27, 98, 104, 138, 93, 190, 113, 162, 29, 87},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 153, 165, 56, 93, 33, 142, 163, 89, 162, 124, 212, 142, 61, 107, 152, 51},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 62, 188, 168, 105, 205, 43, 116, 18, 237, 100, 232, 181, 2, 157, 242, 214},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 90, 25, 211, 50, 31, 54, 146, 46, 151, 172, 134, 124, 38, 24, 36, 63},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{151, 103, 232, 162, 126, 99, 216, 134, 36, 9, 231, 244, 53, 48, 88, 164},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{98, 186, 15, 169, 134, 220, 27, 98, 104, 138, 93, 190, 113, 162, 29, 87},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 163, 194, 41, 127, 235, 32, 213, 154, 152, 246, 224, 156, 176, 255, 214, 174},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 0, 153, 183, 154, 182, 105, 144, 54, 118, 215, 12, 248, 26, 215, 60, 126},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{223, 102, 188, 59, 252, 82, 55, 6, 17, 249, 178, 22, 167, 238, 164, 165, 135, 87, 66, 103, 230, 217, 143, 79, 143, 239, 56, 194, 218, 11, 13, 184},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{125, 26, 71, 57, 17, 197, 47, 94, 34, 145, 8, 158, 212, 254, 242, 36},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{238, 164, 206, 148, 80, 140, 80, 109, 47, 87, 105, 217, 27, 24, 185, 53},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 34, 202, 124, 137, 36, 34, 92, 149, 92, 129, 255, 83, 148, 124, 106, 20},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 220, 247, 15, 132, 252, 148, 60, 228, 114, 187, 227, 63, 131, 157, 169, 163},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 156, 137, 213, 228, 163, 160, 157, 194, 10, 190, 109, 117, 12, 156, 22, 5},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{87, 227, 63, 59, 44, 13, 2, 27, 176, 124, 204, 82, 220, 57, 168, 58},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{51, 133, 183, 176, 188, 0, 51, 238, 129, 102, 85, 26, 101, 197, 255, 152},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 117, 2, 232, 214, 129, 23, 249, 149, 50, 55, 84, 188, 175, 9, 194, 131},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 203, 106, 115, 199, 114, 140, 215, 96, 69, 157, 42, 206, 169, 161, 158, 6},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 173, 7, 28, 95, 98, 30, 208, 108, 12, 175, 140, 195, 214, 150, 95, 245},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{94, 183, 32, 153, 219, 203, 220, 200, 189, 141, 161, 86, 213, 112, 151, 248},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{51, 133, 183, 176, 188, 0, 51, 238, 129, 102, 85, 26, 101, 197, 255, 152},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 137, 172, 203, 184, 177, 46, 73, 228, 7, 68, 199, 11, 28, 211, 237, 195},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 148, 15, 229, 4, 139, 137, 147, 127, 184, 36, 55, 29, 26, 98, 61, 112},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{166, 246, 107, 118, 89, 120, 34, 111, 1, 69, 101, 247, 75, 57, 57, 19, 154, 219, 187, 153, 36, 214, 125, 67, 58, 155, 175, 225, 103, 109, 255, 19},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{49, 30, 215, 241, 103, 74, 106, 14, 203, 180, 184, 116, 67, 234, 15, 242},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{8, 236, 2, 85, 82, 71, 73, 24, 109, 238, 59, 157, 234, 133, 22, 73},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 55, 6, 103, 181, 75, 146, 59, 61, 181, 186, 204, 148, 242, 78, 1, 145},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 140, 98, 150, 106, 163, 205, 174, 224, 56, 249, 42, 100, 142, 16, 245, 127},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 46, 188, 134, 240, 37, 115, 34, 70, 6, 5, 238, 187, 37, 215, 111, 16},
			iv:       []byte("alouepc95malj23l"),
			padder:   zeroPadding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{18, 234, 184, 199, 61, 243, 153, 158, 34, 142, 125, 207, 169, 8, 243, 151},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{205, 165, 182, 49, 227, 252, 104, 57, 57, 66, 144, 220, 126, 20, 78, 221},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 220, 70, 178, 48, 196, 89, 166, 138, 182, 29, 117, 237, 234, 122, 190, 114},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 13, 201, 205, 170, 164, 185, 192, 255, 92, 118, 19, 5, 197, 34, 113, 21},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 17, 102, 224, 72, 125, 246, 10, 131, 36, 118, 104, 156, 210, 232, 181, 190},
			iv:       []byte("alouepc95malj23l"),
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{48, 108, 154, 74, 181, 18, 10, 139, 81, 17, 214, 13, 155, 206, 249, 217},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{205, 165, 182, 49, 227, 252, 104, 57, 57, 66, 144, 220, 126, 20, 78, 221},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 205, 231, 191, 145, 172, 163, 217, 224, 239, 133, 115, 165, 250, 16, 28, 243},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 149, 148, 54, 64, 111, 28, 241, 108, 126, 255, 41, 235, 42, 120, 234, 56},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{54, 89, 15, 187, 17, 112, 140, 191, 66, 174, 219, 46, 123, 43, 126, 190, 235, 238, 150, 255, 118, 173, 205, 233, 2, 155, 4, 21, 53, 110, 150, 144},
			iv:       []byte("alouepc95malj23l"),
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
	}
	// Test
	for i, c := range cases {
		m := NewCBC(c.key)
		m.padder = c.padder
		copy(m.iv, c.iv)
		ret, _ := m.Decrypt(c.data)
		if !bytes.Equal(ret, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, ret, c.expected)
		}
	}

}

func TestCBCIV(t *testing.T) {
	b := make([]byte, BlockSize)
	rand.Read(b)
	m := NewCBC(b[:BlockSize])
	if !bytes.Equal(m.iv, m.IV()) {
		t.Errorf("Result:   %v\nExpected: %v\n", m.IV(), m.iv)
	}
}

func TestCBCSetIV(t *testing.T) {
	// Case
	b := make([]byte, 128)
	rand.Read(b)
	cases := []struct {
		iv       []byte
		expected []byte
	}{
		{iv: b[:16], expected: b[:16]},
	}
	// Test
	m := NewCBC(b[16:32])
	for i, c := range cases {
		m.SetIV(c.iv)
		if !bytes.Equal(m.iv, c.iv) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, m.iv, c.expected)
		}
	}
}
