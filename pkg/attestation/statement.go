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
	GetSource() Subject
	SetSource(Subject)
}

// Subject abstracts a piece of software covered by an attestation
type Subject interface {
	GetName() string
	GetUri() string
	GetDigest() map[string]string
}

func SubjectsMatch(s1, s2 Subject) bool {
	hashes1 := s1.GetDigest()
	hashes2 := s1.GetDigest()
	if len(hashes1) == 0 {
		return false
	}

	// To match, all common algos in s1 and s2 must match and there has
	// to be at least one common algorithm hash.
	matches := 0
	for algo, val1 := range hashes1 {
		if val2, ok := hashes2[algo]; ok {
			matches++
			if val1 != val2 {
				return false
			}
		}
	}
	return matches > 1
}
