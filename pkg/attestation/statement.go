// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

type PredicateType string

// Statement wraps the attestation types in an interface to access its contents
type Statement interface {
	GetSubjects() []Subject
	GetPredicate() Predicate
	GetPredicateType() PredicateType
	GetType() string
	GetVerifications() []*SignatureVerification
}

type Predicate interface {
	GetType() PredicateType
	SetType(PredicateType) error
	GetParsed() any
	GetData() []byte
	GetVerifications() []*SignatureVerification
}

// Subject abstracts a piece of software covered by an attestation
type Subject interface {
	GetName() string
	GetUri() string
	GetDigest() map[string]string
}
