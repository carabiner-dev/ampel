// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

import v1 "github.com/carabiner-dev/ampel/pkg/api/v1"

// Envelope is a construct that wraps the statement, its signature and all the
// verification material. The goal of this abstraction is to get a single
// interface to verify statements, even when all the bits amy be in separate
// files.
type Envelope interface {
	GetStatement() Statement
	GetPredicate() Predicate
	GetSignatures() []Signature
	GetCertificate() Certificate
	GetVerification() *v1.Verification
	Verify() error
}
