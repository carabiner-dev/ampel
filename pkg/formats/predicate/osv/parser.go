// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"fmt"
	"slices"

	protoOSV "github.com/carabiner-dev/osv/go/osv"
	"github.com/puerco/ampel/pkg/attestation"
)

type Parser struct{}

var _ attestation.PredicateParser = (*Parser)(nil)

func New() *Parser {
	return &Parser{}
}

// SupportsType returns true if the OSV parser supports a type
func (*Parser) SupportsType(predTypes ...string) bool {
	return slices.Contains(predTypes, string(PredicateType))
}

// Parse parses a byte slice into a OSV predicate
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	var parser = protoOSV.NewParser()
	results, err := parser.ParseResults(data)
	if err != nil {
		return nil, fmt.Errorf("parsing results into predicate: %w", err)
	}

	if results == nil || (results.Date == nil && len(results.Results) == 0) {
		return nil, attestation.ErrNotCorrectFormat
	}

	return &Predicate{
		Parsed: results,
		Data:   data,
	}, nil
}
