package mode

import "anngo/padding"

type Mode interface {
	Encrypt(*padding.Padding) ([]byte, error)
	Decrypt(*padding.Padding) ([]byte, error)
	Name() string
}
