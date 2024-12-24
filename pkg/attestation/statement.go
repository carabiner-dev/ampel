package attestation

type PredicateType string
type Type string

// Envelope is a construct that wraps the statement, its signature and all the
// verification material. The goal of this abstraction is to get a single
// interface to verify statements, even when all the bits amy be in separate
// files.
type Envelope interface {
	GetStatement() *Statement
	VerifySignature(*VerificationOptions) (*SignatureVerification, error)
}

// Statement wraps the attestation types in an interface to access its contents
type Statement interface {
	Subjects() []Subject
	Predicate() Predicate
	PredicateType() PredicateType
	Type() Type
}

type Predicate interface{}

// Subject abstracts a piece of software covered by an attestation
type Subject interface {
	GetName() string
	GetURI() string
	GetDigest() map[string]string
}
