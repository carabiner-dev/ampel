// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package protobom

import (
	"slices"

	"github.com/carabiner-dev/attestation"

	"github.com/carabiner-dev/ampel/pkg/formats/predicate/cyclonedx"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/spdx"
)

const PredicateType attestation.PredicateType = "application/protobom"

type Parser struct{}

// Ensure this parser implements the interface
var _ attestation.PredicateParser = (*Parser)(nil)

func New() *Parser {
	return &Parser{}
}

var PredicateTypes = []attestation.PredicateType{
	spdx.PredicateType,
	cyclonedx.PredicateType,
}

// Parse generates a generic JSON predicate object from any JSON it gets.
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	// The protobom parser does not support parsing from json data
	return nil, attestation.ErrNotCorrectFormat
}

func (p *Parser) SupportsType(testTypes ...attestation.PredicateType) bool {
	for _, pt := range PredicateTypes {
		if slices.Contains(testTypes, pt) {
			return true
		}
	}
	return false
}
