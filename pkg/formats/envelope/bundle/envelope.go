// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/statement/intoto"
	sigstore "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sirupsen/logrus"
)

type Envelope struct {
	sigstore.Bundle
	Signatures []attestation.Signature
	Statement  attestation.Statement
}

func (e *Envelope) GetStatement() attestation.Statement {
	if e.GetDsseEnvelope() == nil {
		logrus.Error("no dsse envelope in bundle")
		return nil
	}

	//  TODO(puerco): Select parser from statement parsers list
	if e.GetDsseEnvelope().GetPayloadType() != "application/vnd.in-toto+json" {
		logrus.Error("payload is not an intoto attestation")
		return nil
	}

	ip := intoto.Parser{}
	statement, err := ip.Parse(e.GetDsseEnvelope().GetPayload())
	if err != nil {
		logrus.Error("error parsing intoto payload: %w", err)
		return nil
	}
	logrus.Debugf("bundled predicate is of type %s", statement.GetPredicateType())
	return statement
}

func (e *Envelope) GetCertificate() attestation.Certificate {
	return nil
}

func (e *Envelope) GetSignatures() []attestation.Signature {
	return nil
}

func (e *Envelope) VerifySignature() (*attestation.SignatureVerification, error) {
	return nil, nil
}
