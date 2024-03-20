package anngo

const (
	AES128 int = 128
	AES192 int = 192
	AES256 int = 256
)

type AES struct {
	blockSize int
	buffer    []byte
}

func NewAES(buffer []byte, blockSize int) *AES {
	aes := new(AES)
	aes.blockSize = blockSize
	aes.buffer = buffer
	return aes
}
