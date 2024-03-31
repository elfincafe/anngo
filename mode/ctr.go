package mode

type CTR struct {
	name string
}

func NewCTR() *CTR {
	m := new(CTR)
	m.name = "CTR"
	return m
}

func (m *CTR) Encrypt() ([]byte, error) {
	return nil, nil
}

func (m *CTR) Decrypt() ([]byte, error) {
	return nil, nil
}

func (m *CTR) Name() string {
	return m.name
}
