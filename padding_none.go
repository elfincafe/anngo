package anngo

type none struct {
	name string
}

func NewNone() none {
	p := none{name: ""}
	return p
}

func (p none) Pad(b []byte) ([]byte, error) {
	return b, nil
}

func (p none) Unpad(b []byte) ([]byte, error) {
	return b, nil
}

func (p none) Name() string {
	return ""
}
