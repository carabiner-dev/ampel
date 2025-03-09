// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bare

import (
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/sirupsen/logrus"
)

var _ attestation.Envelope = (*Envelope)(nil)

type Envelope struct {
	Statement attestation.Statement
}

func (env *Envelope) GetStatement() attestation.Statement {
	return env.Statement
}

func (_ *Envelope) GetSignatures() []attestation.Signature {
	return []attestation.Signature{}
}

// GetVerifications returns always empty as they are by definition unsigned
func (_ *Envelope) GetVerifications() []*attestation.SignatureVerification {
	return []*attestation.SignatureVerification{}
}

func (env *Envelope) GetCertificate() attestation.Certificate {
	return nil
}

// VerifySignature in bare envelopes never fails but it also always returns
// nil as its signature verification
func (env *Envelope) Verify() error {
	logrus.Debug("Bare envelope mock verification. Returning nil.")
	return nil
}
