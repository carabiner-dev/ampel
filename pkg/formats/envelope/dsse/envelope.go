package dsse

import (
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/statement"
	sigstoreProtoDSSE "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
)

var _ attestation.Envelope = (*Envelope)(nil)

type Envelope struct {
	Signatures []attestation.Signature
	Statement  attestation.Statement
	sigstoreProtoDSSE.Envelope
}

func (env *Envelope) GetStatement() attestation.Statement {
	// This should not happen here.
	s, _ := statement.Parsers.Parse(env.Payload)
	return s
}
func (env *Envelope) GetSignatures() []attestation.Signature {
	return env.Signatures
}
func (env *Envelope) GetCertificate() attestation.Certificate {
	return nil
}
func (env *Envelope) VerifySignature() (*attestation.SignatureVerification, error) {
	return nil, nil
}

// Signature is a clone of the dsse signature struct that can be copied around
type Signature struct {
	KeyID     string
	Signature []byte
}
