// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ampel

import (
	"fmt"
	"slices"

	api "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate/generic"
	"google.golang.org/protobuf/encoding/protojson"
)

var PredicateType = attestation.PredicateType("https://carabiner.dev/ampel/results/v0.0.1")

func NewPredicate() *generic.Predicate {
	return &generic.Predicate{
		Type: PredicateType,
	}
}

func New() *Parser {
	return &Parser{}
}

type Parser struct{}

// Parse reads a data slice and unmarshals it into an ampel predicate
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	set := &api.ResultSet{}
	if err := protojson.Unmarshal(data, set); err != nil {
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}
	pred := NewPredicate()
	pred.Data = data
	pred.Parsed = set
	return pred, nil
}

func (*Parser) SupportsType(predTypes ...string) bool {
	return slices.Contains(predTypes, string(PredicateType))
}
