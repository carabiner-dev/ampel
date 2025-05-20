// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bare

import (
	"github.com/sirupsen/logrus"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
)

var _ attestation.Envelope = (*Envelope)(nil)

type Envelope struct {
	Statement attestation.Statement
}

func (env *Envelope) GetStatement() attestation.Statement {
	return env.Statement
}

func (env *Envelope) GetPredicate() attestation.Predicate {
	if s := env.GetStatement(); s != nil {
		return env.GetStatement().GetPredicate()
	}
	return nil
}

func (*Envelope) GetSignatures() []attestation.Signature {
	return []attestation.Signature{}
}

// GetVerifications returns always empty as they are by definition unsigned
func (*Envelope) GetVerification() *api.Verification {
	return nil
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
