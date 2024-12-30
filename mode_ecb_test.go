package anngo

import (
	"testing"
)

func TestNewECB(t *testing.T) {
}

func TestECBEncrypt(t *testing.T) {
	// Zero
	// <aes-128-ecb>
	// Key:    0123456789abcdef
	// Data:   abcdefghijklmn
	// Result: [55, 21, 77, 54, 24, 109, 250, 166, 56, 152, 91, 46, 107, 97, 56, 134]
	// <aes-128-ecb>
	// Key:    0123456789abcdef
	// Data:   abcdefghijklmno
	// Result: [205, 215, 47, 196, 28, 56, 247, 118, 68, 155, 191, 77, 166, 186, 198, 250]
	// <aes-128-ecb>
	// Key:    0123456789abcdef
	// Data:   abcdefghijklmnop
	// Result: [133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 55, 114, 34, 224, 97, 169, 36, 197, 145, 205, 156, 39, 234, 22, 62, 212]
	// <aes-128-ecb>
	// Key:    0123456789abcdef
	// Data:   abcdefghijklmnopq
	// Result: [133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 199, 82, 84, 255, 34, 17, 34, 147, 205, 245, 192, 29, 244, 124, 68, 51]
	// <aes-128-ecb>
	// Key:    0123456789abcdef
	// Data:   abcdefghijklmnopqr
	// Result: [133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 75, 163, 126, 99, 191, 217, 232, 162, 241, 121, 251, 177, 126, 74, 145, 220]
	// <aes-192-ecb>
	// Key:    0123456789abcdefghijklmn
	// Data:   abcdefghijklmn
	// Result: [204, 148, 233, 40, 238, 195, 248, 21, 162, 8, 190, 215, 182, 16, 108, 0]
	// <aes-192-ecb>
	// Key:    0123456789abcdefghijklmn
	// Data:   abcdefghijklmno
	// Result: [34, 206, 80, 92, 182, 165, 35, 191, 10, 224, 158, 170, 168, 52, 189, 161]
	// <aes-192-ecb>
	// Key:    0123456789abcdefghijklmn
	// Data:   abcdefghijklmnop
	// Result: [113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 3, 102, 117, 172, 27, 118, 83, 91, 199, 54, 56, 96, 195, 102, 146, 105]
	// <aes-192-ecb>
	// Key:    0123456789abcdefghijklmn
	// Data:   abcdefghijklmnopq
	// Result: [113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 60, 170, 41, 177, 133, 79, 181, 24, 155, 44, 59, 226, 97, 120, 164, 136]
	// <aes-192-ecb>
	// Key:    0123456789abcdefghijklmn
	// Data:   abcdefghijklmnopqr
	// Result: [113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 223, 113, 2, 50, 212, 171, 241, 193, 192, 14, 10, 213, 214, 110, 201, 5]
	// <aes-256-ecb>
	// Key:    0123456789abcdefghijklmnopqrstuv
	// Data:   abcdefghijklmn
	// Result: [125, 143, 121, 9, 127, 221, 251, 238, 232, 218, 225, 174, 152, 88, 63, 196]
	// <aes-256-ecb>
	// Key:    0123456789abcdefghijklmnopqrstuv
	// Data:   abcdefghijklmno
	// Result: [185, 120, 176, 119, 188, 33, 56, 139, 180, 61, 193, 193, 140, 156, 83, 117]
	// <aes-256-ecb>
	// Key:    0123456789abcdefghijklmnopqrstuv
	// Data:   abcdefghijklmnop
	// Result: [130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 204, 161, 137, 114, 125, 62, 36, 179, 84, 10, 8, 168, 144, 169, 66, 83]
	// <aes-256-ecb>
	// Key:    0123456789abcdefghijklmnopqrstuv
	// Data:   abcdefghijklmnopq
	// Result: [130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 142, 222, 157, 213, 110, 182, 24, 122, 107, 57, 185, 144, 211, 163, 120, 33]
	// <aes-256-ecb>
	// Key:    0123456789abcdefghijklmnopqrstuv
	// Data:   abcdefghijklmnopqr
	// Result: [130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 252, 18, 148, 68, 155, 1, 169, 179, 205, 164, 133, 86, 121, 70, 34, 236]
}
