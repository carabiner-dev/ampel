package transformer

import "time"

// Factory returns a list of transformers from
// a list of string identifiers
type Factory struct {
}

func (tf *Factory) Get([]string) ([]*Transformer, error) {
}

// Transformer is an interface that models a predicate transformer
type Transformer interface {
	Transform([]*Predicate) (*Predicate, error)
}

type Info struct {
	Identifier string
	Version    string
	Hashes     map[string]string
}

// InputRecord records the inputs that went into a predicate
// transformation process.
type InputRecord struct {
	Type     PredicateType
	Subjects []Subject
	Hashes   map[string]string
}

// OutputRecord is a struct that catpures metadata about
// the outputs resulting from a tranformer run.
type OutputRecord struct {
	Hashes map[string]string
	Type   PredicateType
}

// Record is a struct that records a run
// of a transformer.
type Record struct {
	Date        *time.Time
	Transformer TransformerInfo
	Inputs      []TransformerInputRecord
	Output      []TransformerOutputRecord
}
