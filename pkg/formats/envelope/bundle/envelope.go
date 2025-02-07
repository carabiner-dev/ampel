// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"crypto/x509"
	"fmt"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/statement/intoto"
	sigstore "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
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
	if e.Bundle.GetVerificationMaterial() == nil {
		return nil, fmt.Errorf("no verification material found in bundle")
	}

	cert := e.Bundle.GetVerificationMaterial().GetCertificate()
	if cert == nil {
		return nil, fmt.Errorf("no certificate found in bundle")
	}

	x509cert, err := x509.ParseCertificate(cert.GetRawBytes())
	if err != nil {
		return nil, fmt.Errorf("parsing cert: %w", err)
	}

	summary, err := certificate.SummarizeCertificate(x509cert)
	if err != nil {
		return nil, fmt.Errorf("summarizing cert: %w", err)
	}

	logrus.Debug("Parsed sigstore cert data:")
	logrus.Debugf("  OIDC issuer:  %s", summary.Issuer)
	logrus.Debugf("  Cert SAN:     %s", summary.SubjectAlternativeName)
	logrus.Debugf("  Cert Issuer:  %s", summary.CertificateIssuer)

	logrus.Warn("SIGNATURE VALIDATION IS MOCKED, DO NOT USE YET")
	return &attestation.SignatureVerification{
		SigstoreCertData: summary,
	}, nil
}
