package mode

type Mode interface {
	Encrypt() ([]byte, error)
	Decrypt() ([]byte, error)
	Name() string
}
