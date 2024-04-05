package padding

type Padding interface {
	Pad() ([]byte, error)
	Unpad() ([]byte, error)
	Name() string
}
