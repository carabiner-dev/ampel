// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"fmt"
	"slices"
	"strings"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
	v02 "github.com/carabiner-dev/ampel/pkg/formats/predicate/slsa/provenance/v02"
	v10 "github.com/carabiner-dev/ampel/pkg/formats/predicate/slsa/provenance/v10"
	v11 "github.com/carabiner-dev/ampel/pkg/formats/predicate/slsa/provenance/v11"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	PredicateType02 = attestation.PredicateType("https://slsa.dev/provenance/v0.2")
	PredicateType10 = attestation.PredicateType("https://slsa.dev/provenance/v1")
	PredicateType11 = attestation.PredicateType("https://slsa.dev/provenance/v1.1")
)

// Single version parsers
type ParserV10 struct{}
type ParserV11 struct{}
type ParserV02 struct{}

func NewParserV02() *ParserV02 {
	return &ParserV02{}
}

func NewParserV10() *ParserV10 {
	return &ParserV10{}
}

func NewParserV11() *ParserV11 {
	return &ParserV11{}
}

func (_ *ParserV10) Parse(data []byte) (attestation.Predicate, error) {
	return parseProvenanceV10(data)
}

func (_ *ParserV11) Parse(data []byte) (attestation.Predicate, error) {
	return parseProvenanceV11(data)
}

func (_ *ParserV02) Parse(data []byte) (attestation.Predicate, error) {
	return parseProvenanceV02(data)
}

func (_ *ParserV10) SupportsType(types ...attestation.PredicateType) bool {
	return slices.Contains(types, PredicateType10)
}

func (_ *ParserV11) SupportsType(types ...attestation.PredicateType) bool {
	return slices.Contains(types, PredicateType11)
}

func (_ *ParserV02) SupportsType(types ...attestation.PredicateType) bool {
	return slices.Contains(types, PredicateType02)
}

func parseProvenanceV11(data []byte) (attestation.Predicate, error) {
	var provenance = v11.Provenance{}
	if err := protojson.Unmarshal(data, &provenance); err != nil {
		// Transform the error to our wrong type error
		if strings.Contains(err.Error(), "proto:") &&
			strings.Contains(err.Error(), "syntax error") &&
			strings.Contains(err.Error(), "invalid value") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("error parsing v11 provenance predicate: %s", err)
	}
	return &generic.Predicate{
		Type:   PredicateType11,
		Parsed: &provenance,
		Data:   data,
	}, nil
}

func parseProvenanceV02(data []byte) (attestation.Predicate, error) {
	var provenance = v02.Provenance{}
	if err := protojson.Unmarshal(data, &provenance); err != nil {
		// Transform the error to our wrong type error
		if strings.Contains(err.Error(), "proto:") &&
			strings.Contains(err.Error(), "syntax error") &&
			strings.Contains(err.Error(), "invalid value") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("error parsing v11 provenance predicate: %s", err)
	}
	return &generic.Predicate{
		Type:   PredicateType02,
		Parsed: &provenance,
		Data:   data,
	}, nil
}

func parseProvenanceV10(data []byte) (attestation.Predicate, error) {
	var provenance = v10.Provenance{}
	if err := protojson.Unmarshal(data, &provenance); err != nil {
		// Transform the error to our wrong type error
		if strings.Contains(err.Error(), "proto:") &&
			strings.Contains(err.Error(), "syntax error") &&
			strings.Contains(err.Error(), "invalid value") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("error parsing v11 provenance predicate: %s", err)
	}
	return &generic.Predicate{
		Type:   PredicateType10,
		Parsed: &provenance,
		Data:   data,
	}, nil
}
