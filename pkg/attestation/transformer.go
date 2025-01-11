package attestation

import "time"

// Transformer is an interface that models a predicate transformer
type Transformer interface {
	Transform([]*Predicate) (*Predicate, error)
}

type TransformerInfo struct {
	Identifier string
	Version    string
	Hashes     map[string]string
}

// TransformerInputRecord records the inputs that went into a predicate
// transformation process.
type TransformerInputRecord struct {
	Type     PredicateType
	Subjects []Subject
	Hashes   map[string]string
}

// TransformerOutputRecord is a struct that catpures metadata about
// the outputs resulting from a tranformer run.
type TransformerOutputRecord struct {
	Hashes map[string]string
	Type   PredicateType
}

// TransformationEvidence is a struct that records a run
// of a transformer.
type TransformationRecord struct {
	Date        *time.Time
	Transformer TransformerInfo
	Inputs      []TransformerInputRecord
	Output      []TransformerOutputRecord
}
