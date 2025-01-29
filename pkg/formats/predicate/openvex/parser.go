// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package openvex

import (
	"fmt"
	"slices"

	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate/generic"
)

type Parser struct{}

var PredicateType = attestation.PredicateType("https://openvex.dev/ns")
var _ attestation.PredicateParser = (*Parser)(nil)

func New() *Parser {
	return &Parser{}
}

func (*Parser) SupportsType(predTypes ...string) bool {
	return slices.Contains(predTypes, string(PredicateType))
}

// Parse parses openvex predicate data
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	doc, err := openvex.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing VEX predicate: %w", err)
	}
	if doc.Context == "" {
		return nil, attestation.ErrNotCorrectFormat
	}
	return &generic.Predicate{
		Type:   PredicateType,
		Parsed: doc,
		Data:   data,
	}, nil
}
