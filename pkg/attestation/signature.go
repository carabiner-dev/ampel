// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

import "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

// Signature abstracts a signature. At least for now.
type Signature interface{}
type Certificate interface{}

// Results of the signature verification process
type SignatureVerification struct {
	SigstoreCertData certificate.Summary
}

// Verification options abstracts the different options that can be tweaked
// to verify the various signature types
type VerificationOptions interface{}
