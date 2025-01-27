// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	v1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	"github.com/puerco/ampel/pkg/attestation"
)

var PredicateType = attestation.PredicateType("https://slsa.dev/provenance/v1")

type Predicate struct {
	Type   attestation.PredicateType
	Parsed *v1.Provenance
	Data   []byte
}

func (p *Predicate) GetType() attestation.PredicateType {
	if p.Type == "" {
		return PredicateType
	}
	return p.Type
}

func (p *Predicate) GetData() []byte {
	return p.Data
}

func (p *Predicate) GetParsed() any {
	return p.Parsed
}
