// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package generic is a generic predicate that can be used as a wrapper for
// most predicate payloads
package generic

import (
	"encoding/json"

	"github.com/carabiner-dev/attestation"
)

type Predicate struct {
	Type         attestation.PredicateType `json:"_type"`
	Parsed       any
	Source       attestation.Subject      `json:"-"`
	Data         []byte                   `json:"-"`
	Verification attestation.Verification `json:"-"`
}

func (p *Predicate) GetType() attestation.PredicateType { return p.Type }
func (p *Predicate) SetType(pt attestation.PredicateType) error {
	// TODO(puerco): Ensure this is a URI
	p.Type = pt
	return nil
}
func (p *Predicate) GetParsed() any                              { return p.Parsed }
func (p *Predicate) GetData() []byte                             { return p.Data }
func (p *Predicate) GetOrigin() attestation.Subject              { return p.Source }
func (p *Predicate) SetOrigin(src attestation.Subject)           { p.Source = src }
func (p *Predicate) SetVerification(vf attestation.Verification) { p.Verification = vf }

// GetVerifications returns the signature verifications from the predicate
func (p *Predicate) GetVerification() attestation.Verification {
	return p.Verification
}

// MarshalJSON implements the JSON marshaler interface. It reuses any pre
// parsed data already stored in the predicate.
func (p *Predicate) MarshalJSON() ([]byte, error) {
	// If the predicate was already marshalled, reuse the output
	if p.Data != nil {
		return p.Data, nil
	}

	// Otherwise, marshal the value
	return json.Marshal(p.Parsed)
}
