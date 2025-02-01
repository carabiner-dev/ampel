// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

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
	if e.VerificationMaterial == nil {
		return nil, errors.New("bundle does not have verification material")
	}
	if e.VerificationMaterial.GetX509CertificateChain() == nil {
		return nil, errors.New("bundle does not include the certificate chain")
	}

	certs := e.GetVerificationMaterial().GetX509CertificateChain().GetCertificates()
	if certs == nil || len(certs) == 0 {
		return nil, errors.New("certificate chain does not include certs")
	}

	// Decode the base64 encoded cert
	//logrus.Debugf("CERT:\n%s\n", string(certs[0].RawBytes))

	// Decode the cert to access its fields
	pemb, _ := pem.Decode(certs[0].RawBytes)
	cert, err := x509.ParseCertificate(pemb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("decoding pem block from cert: %s", err)
	}

	data := &attestation.SigstoreCertData{
		Identity: cert.Subject.CommonName,
	}
	// cert.Issuer must be sigstore
	for _, e := range cert.Extensions {
		switch e.Id.String() {
		case "1.3.6.1.4.1.57264.1.1", "1.3.6.1.4.1.57264.1.8":
			var s string
			if _, err := asn1.Unmarshal(e.Value, &s); err != nil {
				//return nil, fmt.Errorf("malformed certificate extension %s: %w", e.Id.String(), err)
			}
			data.Issuer = s
		case "2.5.29.17":
			var s string
			if _, err := asn1.Unmarshal(e.Value, &s); err != nil {
				//return nil, fmt.Errorf("malformed certificate extension %s: %w", e.Value, err)
			}
			// This is a weird ASN decode bug coming from the sigstore cert
			data.Identity = string(e.Value[4:])
		default:
			// logrus.Infof("%s: %s", e.Id.String(), s)
		}
	}

	logrus.Debug("Parsed sigstore cert data:")
	logrus.Debugf("  Cert issuer:   %s", data.Issuer)
	logrus.Debugf("  Cert identity: %s", data.Identity)

	logrus.Warn("SIGNATURE VALIDATION IS MOCKED, DO NOT USE YET")
	return &attestation.SignatureVerification{
		SigstoreCertData: data,
	}, nil
}
