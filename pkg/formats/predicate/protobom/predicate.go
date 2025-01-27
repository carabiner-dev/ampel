// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package protobom

import (
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/puerco/ampel/pkg/attestation"
)

const PredicateType attestation.PredicateType = "application/protobom"

type Predicate struct {
	Data   []byte
	Parsed *sbom.Document
}

func (*Predicate) GetType() attestation.PredicateType {
	return PredicateType
}

func (p *Predicate) GetData() []byte {
	return p.Data
}

func (p *Predicate) GetParsed() any {
	return p.Parsed
}
