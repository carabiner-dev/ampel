// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

// Signature abstracts a signature. At least for now.
type Signature interface{}
type Certificate interface{}

// Results of the signature verification process
type SignatureVerification struct {
	SigstoreCertData *SigstoreCertData
}

type SigstoreCertData struct {
	Issuer   string
	Identity string
}

// Verification options abstracts the different options that can be tweaked
// to verify the various signature types
type VerificationOptions interface{}
