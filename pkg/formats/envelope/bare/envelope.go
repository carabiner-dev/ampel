package bare

import "github.com/puerco/ampel/pkg/attestation"

var _ attestation.Envelope = (*Envelope)(nil)

type Envelope struct {
	Statement attestation.Statement
}

func (env *Envelope) GetStatement() attestation.Statement {
	return env.Statement
}
func (env *Envelope) GetSignatures() []attestation.Signature {
	return []attestation.Signature{}
}
func (env *Envelope) GetCertificate() attestation.Certificate {
	return nil
}
func (env *Envelope) VerifySignature() (*attestation.SignatureVerification, error) {
	return nil, nil
}
