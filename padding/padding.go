package padding

type Padding interface {
	Pad(int) ([]byte, error)
	Unpad(int) ([]byte, error)
	Name() string
}
