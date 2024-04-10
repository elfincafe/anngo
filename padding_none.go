package anngo

type (
	none struct {
		name string
	}
)

func newNone() none {
	return none{name: ""}
}

func (p none) Name() string {
	return ""
}

func (p none) Pad(v []byte) ([]byte, error) {
	return v, nil
}

func (p none) Unpad(v []byte) ([]byte, error) {
	return v, nil
}
