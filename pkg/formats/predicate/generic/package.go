// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package generic is a generic predicate that can be used as a wrapper for
// most predicate payloads
package generic

import (
	"encoding/json"

	"github.com/carabiner-dev/ampel/pkg/attestation"
)

type Predicate struct {
	Type   attestation.PredicateType `json:"_type"`
	Parsed any
	Data   []byte `json:"-"`
}

func (p *Predicate) GetType() attestation.PredicateType { return p.Type }
func (p *Predicate) SetType(pt attestation.PredicateType) error {
	// TODO(puerco): Ensure this is a URI
	p.Type = pt
	return nil
}
func (p *Predicate) GetParsed() any  { return p.Parsed }
func (p *Predicate) GetData() []byte { return p.Data }
func (p *Predicate) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Parsed)
}
