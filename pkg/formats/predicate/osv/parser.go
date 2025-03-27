// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"fmt"
	"slices"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
	protoOSV "github.com/carabiner-dev/osv/go/osv"
)

var PredicateType = attestation.PredicateType("https://ossf.github.io/osv-schema/results@v1.6.7")

type Parser struct{}

var _ attestation.PredicateParser = (*Parser)(nil)

func New() *Parser {
	return &Parser{}
}

// SupportsType returns true if the OSV parser supports a type
func (*Parser) SupportsType(predTypes ...attestation.PredicateType) bool {
	return slices.Contains(predTypes, PredicateType)
}

// Parse parses a byte slice into a OSV predicate
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	parser := protoOSV.NewParser()
	results, err := parser.ParseResults(data)
	if err != nil {
		return nil, fmt.Errorf("parsing results into predicate: %w", err)
	}

	if results == nil || (results.Date == nil && len(results.Results) == 0) {
		return nil, attestation.ErrNotCorrectFormat
	}

	return &generic.Predicate{
		Type:   PredicateType,
		Parsed: results,
		Data:   data,
	}, nil
}
