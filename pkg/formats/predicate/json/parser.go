// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package json

import (
	gojson "encoding/json"
	"fmt"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
)

const PredicateType attestation.PredicateType = "text/json"

type Parser struct{}
type DataMap map[string]any

// Ensure this parser implements the interface
var _ attestation.PredicateParser = (*Parser)(nil)

// Parse generates a generic JSON predicate object from any JSON it gets.
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	pred := &generic.Predicate{
		Type: PredicateType,
		Data: data,
	}
	parsedData := DataMap{}
	if err := gojson.Unmarshal(pred.Data, &parsedData); err != nil {
		return nil, fmt.Errorf("parsing raw json data: %w", err)
	}
	pred.Parsed = parsedData
	return pred, nil
}

// SupportsType always returns true because the json parser
// is a catchall predicate parser.
func (p *Parser) SupportsType(testTypes ...attestation.PredicateType) bool {
	return true
}

type OptionFunc func(*generic.Predicate) error

func WithJson(data []byte) OptionFunc {
	return func(pred *generic.Predicate) error {
		// Parse into a generic structure
		var parsed = DataMap{}
		if err := gojson.Unmarshal(data, &parsed); err != nil {
			return fmt.Errorf("parsing predicate json: %w", err)
		}

		pred.Data = data
		pred.Parsed = parsed
		return nil
	}
}

func WithType(pt attestation.PredicateType) OptionFunc {
	return func(pred *generic.Predicate) error {
		pred.Type = pt
		return nil
	}
}

func New(optsFn ...OptionFunc) (*generic.Predicate, error) {
	var pred = &generic.Predicate{
		Type: PredicateType,
	}
	for _, of := range optsFn {
		if err := of(pred); err != nil {
			return nil, err
		}
	}
	return pred, nil
}
