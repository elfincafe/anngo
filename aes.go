package anngo

const (
	AES128 = 128
	AES192 = 192
	AES256 = 256
)

type Aes struct {
	blockSize int
	buffer    []byte
}

func NewAes(buffer []byte, blockSize int) *Aes {
	aes := new(Aes)
	aes.blockSize = blockSize
	aes.buffer = buffer
	return aes
}
