package principal

type Hash struct {
	Values map[string]string
}

type HashOption interface{}

type Resource interface {
	Hash() Hash
}
