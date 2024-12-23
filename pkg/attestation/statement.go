package attestation

type SignatureVerification struct{}
type VerificationOptions interface{}

type Predicate interface{}
type Subject interface{}

type Statement interface {
	Subjects() []Subject
	Predicate() Predicate
	Type() string
	VerifySignature(...VerificationOptions) (*SignatureVerification, error)
}
