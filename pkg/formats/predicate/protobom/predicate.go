// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package protobom

import (
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/protobom/protobom/pkg/sbom"
)

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
