// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package openeox

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate/generic"
)

var PredicateType = attestation.PredicateType("https://openeox.org/schema-0.2.0.json")

type Parser struct{}

func New() *Parser {
	return &Parser{}
}

func (*Parser) SupportsType(predTypes ...string) bool {
	return slices.Contains(predTypes, string(PredicateType))
}

func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	var eox = &EOX{}
	if err := json.Unmarshal(data, eox); err != nil {
		return nil, fmt.Errorf("parsing EOX data: %w", err)
	}

	// Check we are actually consuming and openeox file
	if (eox.Schema != "" && eox.Schema != string(PredicateType)) || eox.EOLDate == nil {
		return nil, attestation.ErrNotCorrectFormat
	}

	return &generic.Predicate{
		Type:   PredicateType,
		Parsed: eox,
		Data:   data,
	}, nil
}
