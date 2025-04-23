// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"fmt"
	"slices"
	"strings"

	vsa "github.com/in-toto/attestation/go/predicates/vsa/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
)

var PredicateType = attestation.PredicateType("https://slsa.dev/verification_summary/v1")

func NewParser() *Parser {
	return &Parser{}
}

type Parser struct{}

func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	provenance := vsa.VerificationSummary{}
	if err := protojson.Unmarshal(data, &provenance); err != nil {
		// Transform the error to our wrong type error
		if strings.Contains(err.Error(), "proto:") &&
			strings.Contains(err.Error(), "syntax error") &&
			strings.Contains(err.Error(), "invalid value") {
			return nil, attestation.ErrNotCorrectFormat
		} else if strings.Contains(err.Error(), "proto:") &&
			strings.Contains(err.Error(), `unknown field "`) {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("error parsing SLSA/v0.2 provenance predicate: %w", err)
	}
	return &generic.Predicate{
		Type:   PredicateType,
		Parsed: &provenance,
		Data:   data,
	}, nil
}

func (*Parser) SupportsType(types ...attestation.PredicateType) bool {
	return slices.Contains(types, PredicateType)
}
