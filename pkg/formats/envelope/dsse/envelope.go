// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/statement"
	sigstoreProtoDSSE "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
)

var _ attestation.Envelope = (*Envelope)(nil)

type Envelope struct {
	Signatures    []attestation.Signature
	Statement     attestation.Statement
	Verifications []*attestation.SignatureVerification
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

// TODO(puerco): Implement
func (env *Envelope) Verify() error {
	return nil
}

// GetVerifications returns the envelop signtature verifications
func (env *Envelope) GetVerifications() []*attestation.SignatureVerification {
	if env.GetStatement() == nil {
		return nil
	}
	return env.GetStatement().GetVerifications()
}

// Signature is a clone of the dsse signature struct that can be copied around
type Signature struct {
	KeyID     string
	Signature []byte
}
