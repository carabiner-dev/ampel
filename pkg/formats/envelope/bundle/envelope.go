// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"crypto/x509"
	"fmt"

	sigstore "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sirupsen/logrus"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/statement/intoto"
)

type Envelope struct {
	sigstore.Bundle
	Signatures    []attestation.Signature
	Statement     attestation.Statement
	Verifications []*attestation.SignatureVerification
}

func (e *Envelope) GetStatementOrErr() (attestation.Statement, error) {
	if e.Statement != nil {
		return e.Statement, nil
	}
	if e.GetDsseEnvelope() == nil {
		return nil, fmt.Errorf("no dsse envelope found in bundle")
	}

	//  TODO(puerco): Select parser from statement parsers list
	if e.GetDsseEnvelope().GetPayloadType() != "application/vnd.in-toto+json" {
		return nil, fmt.Errorf("payload is not an intoto attestation")
	}

	// So, for now, this is fixed to the intoto parser
	ip := intoto.Parser{}
	statement, err := ip.Parse(e.GetDsseEnvelope().GetPayload())
	if err != nil {
		return nil, fmt.Errorf("parsing intoto payload: %w", err)
	}

	// Store the statement
	e.Statement = statement
	logrus.Debugf("Bundled predicate is of type %s", statement.GetPredicateType())
	return statement, nil
}

func (e *Envelope) GetStatement() attestation.Statement {
	statement, err := e.GetStatementOrErr()
	if err != nil {
		logrus.Debugf("ERROR: %v", err)
		return nil
	}
	return statement
}

func (e *Envelope) GetCertificate() attestation.Certificate {
	return nil
}

func (e *Envelope) GetSignatures() []attestation.Signature {
	return nil
}

// GetVerifications returns the signtature verifications stored in the
// predicate (via the statement)
func (env *Envelope) GetVerifications() []*attestation.SignatureVerification {
	if env.GetStatement() == nil {
		return nil
	}
	return env.GetStatement().GetVerifications()
}

func (e *Envelope) Verify() error {
	if e.GetVerificationMaterial() == nil {
		return fmt.Errorf("no verification material found in bundle")
	}

	cert := e.Bundle.GetVerificationMaterial().GetCertificate()
	if cert == nil {
		return fmt.Errorf("no certificate found in bundle")
	}

	x509cert, err := x509.ParseCertificate(cert.GetRawBytes())
	if err != nil {
		return fmt.Errorf("parsing cert: %w", err)
	}

	summary, err := certificate.SummarizeCertificate(x509cert)
	if err != nil {
		return fmt.Errorf("summarizing cert: %w", err)
	}

	logrus.Debug("Parsed sigstore cert data:")
	logrus.Debugf("  OIDC issuer:  %s", summary.Issuer)
	logrus.Debugf("  Cert SAN:     %s", summary.SubjectAlternativeName)
	logrus.Debugf("  Cert Issuer:  %s", summary.CertificateIssuer)

	logrus.Warn("SIGNATURE VALIDATION IS MOCKED, DO NOT USE YET")

	//nolint:gocritic // Under construction
	// ver := &attestation.SignatureVerification{
	// 	SigstoreCertData: summary,
	// }
	return nil
}

func (e *Envelope) UnmarshalJSON(data []byte) error {
	p := Parser{}

	if err := p.unmarshalTo(e, data); err != nil {
		return fmt.Errorf("parsing bundle: %w", err)
	}

	return nil
}
