package attestation

type Type string

// Statement wraps the attestation types in an interface to access its contents
type Statement interface {
	GetSubjects() []Subject
	GetPredicate() Predicate
	GetPredicateType() string
	GetType() string
}

type Predicate interface{}

// Subject abstracts a piece of software covered by an attestation
type Subject interface {
	GetName() string
	GetUri() string
	GetDigest() map[string]string
}
