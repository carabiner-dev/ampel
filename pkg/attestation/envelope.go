package attestation

// Envelope is a construct that wraps the statement, its signature and all the
// verification material. The goal of this abstraction is to get a single
// interface to verify statements, even when all the bits amy be in separate
// files.
type Envelope interface {
	GetStatement() Statement
	GetSignatures() []Signature
	GetCertificate() Certificate
	VerifySignature() (*SignatureVerification, error)
}
