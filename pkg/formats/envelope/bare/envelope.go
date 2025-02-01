// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bare

import (
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/sirupsen/logrus"
)

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

// VerifySignature in bare envelopes never fails but it also always returns
// nil as its signature verification
func (env *Envelope) VerifySignature() (*attestation.SignatureVerification, error) {
	logrus.Debug("Bare envelope mock verification. Returning nil.")
	return nil, nil
}
