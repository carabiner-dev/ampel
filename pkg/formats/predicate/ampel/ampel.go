// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ampel

import (
	"fmt"
	"slices"

	"github.com/carabiner-dev/attestation"
	papi "github.com/carabiner-dev/policy/api/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
)

var (
	PredicateTypeResults   = attestation.PredicateType("https://carabiner.dev/ampel/results/v0.0.1")
	PredicateTypePolicy    = attestation.PredicateType("https://carabiner.dev/ampel/policy/v0.0.1")
	PredicateTypePolicySet = attestation.PredicateType("https://carabiner.dev/ampel/policyset/v0.0.1")

	PredicateTypes = []attestation.PredicateType{
		PredicateTypeResults, PredicateTypePolicy, PredicateTypePolicySet,
	}
)

func NewPredicate() *generic.Predicate {
	return &generic.Predicate{
		Type: PredicateTypeResults,
	}
}

func New() *Parser {
	return &Parser{}
}

type Parser struct{}

// Parse reads a data slice and unmarshals it into an ampel predicate
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	att, err := p.ParseResultsPredicate(data)
	if err == nil {
		return att, nil
	}

	att, err = p.ParsePolicySetPredicate(data)
	if err == nil {
		return att, nil
	}

	att, err = p.ParsePolicyPredicate(data)
	if err == nil {
		return att, nil
	}
	return nil, attestation.ErrNotCorrectFormat
}

func (p *Parser) ParsePolicySetPredicate(data []byte) (attestation.Predicate, error) {
	policy := &papi.PolicySet{}
	if err := protojson.Unmarshal(data, policy); err != nil {
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}
	pred := NewPredicate()
	pred.Type = PredicateTypePolicySet
	pred.Data = data
	pred.Parsed = policy
	return pred, nil
}

func (p *Parser) ParsePolicyPredicate(data []byte) (attestation.Predicate, error) {
	policy := &papi.Policy{}
	if err := protojson.Unmarshal(data, policy); err != nil {
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}
	pred := NewPredicate()
	pred.Type = PredicateTypePolicy
	pred.Data = data
	pred.Parsed = policy
	return pred, nil
}

func (p *Parser) ParseResultsPredicate(data []byte) (attestation.Predicate, error) {
	set := &papi.ResultSet{}
	if err := protojson.Unmarshal(data, set); err != nil {
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}
	pred := NewPredicate()
	pred.Type = PredicateTypeResults
	pred.Data = data
	pred.Parsed = set
	return pred, nil
}

func (*Parser) SupportsType(predTypes ...attestation.PredicateType) bool {
	for _, p := range PredicateTypes {
		if slices.Contains(predTypes, p) {
			return true
		}
	}
	return false
}
