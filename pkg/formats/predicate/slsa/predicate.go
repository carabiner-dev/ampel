// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"github.com/puerco/ampel/pkg/attestation"
	v10 "github.com/puerco/ampel/pkg/formats/predicate/slsa/provenance/v10"
	v11 "github.com/puerco/ampel/pkg/formats/predicate/slsa/provenance/v11"
)

var (
	PredicateType10 = attestation.PredicateType("https://slsa.dev/provenance/v1")
	PredicateType11 = attestation.PredicateType("https://slsa.dev/provenance/v1.1")
)

type ProvenancePredicate interface {
}

type Predicate struct {
	Type   attestation.PredicateType
	Parsed ProvenancePredicate
	Data   []byte
}

func (p *Predicate) GetType() attestation.PredicateType {
	if p.Type != "" {
		return p.Type
	}

	switch p.Parsed.(type) {
	case v10.Provenance:
		return PredicateType10
	case v11.Provenance:
		return PredicateType11
	default:
		return ""
	}
}

func (p *Predicate) GetData() []byte {
	return p.Data
}

func (p *Predicate) GetParsed() any {
	return p.Parsed
}
