package padding

var (
	byteMap1 = map[int]byte{
		0: 0x00, 1: 0x01, 2: 0x02, 3: 0x03, 4: 0x04,
		5: 0x05, 6: 0x06, 7: 0x07, 8: 0x08, 9: 0x09,
		10: 0x0a, 11: 0x0b, 12: 0x0c, 13: 0x0d, 14: 0x0e,
		15: 0x0f, 16: 0x10, 17: 0x11, 18: 0x12, 19: 0x13,
		20: 0x14, 21: 0x15, 22: 0x16, 23: 0x17, 24: 0x18,
		25: 0x19, 26: 0x1a, 27: 0x1b, 28: 0x1c, 29: 0x1d,
		30: 0x1e, 31: 0x1f,
	}
	byteMap2 = map[byte]int{
		0x00: 0, 0x01: 1, 0x02: 2, 0x03: 3, 0x04: 4,
		0x05: 5, 0x06: 6, 0x07: 7, 0x08: 8, 0x09: 9,
		0x0a: 10, 0x0b: 11, 0x0c: 12, 0x0d: 13, 0x0e: 14,
		0x0f: 15, 0x10: 16, 0x11: 17, 0x12: 18, 0x13: 19,
		0x14: 20, 0x15: 21, 0x16: 22, 0x17: 23, 0x18: 24,
		0x19: 25, 0x1a: 26, 0x1b: 27, 0x1c: 28, 0x1d: 29,
		0x1e: 30, 0x1f: 31,
	}
)

type Padding interface {
	Pad(int) ([]byte, error)
	Unpad(int) ([]byte, error)
	Name() string
}

func paddingLength(blockSize, length int) int {
	blockBytes := int(blockSize / 8)
	if length == 0 {
		return 0
	}
	rest := length % blockBytes
	if rest == 0 {
		return 0
	}
	return blockBytes - length%blockBytes
}
