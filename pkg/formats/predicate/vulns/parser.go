// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vulns

import (
	"fmt"
	"slices"
	"strings"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
	v02 "github.com/in-toto/attestation/go/predicates/vulns/v02"
	"google.golang.org/protobuf/encoding/protojson"
)

var PredicateTypeV2 = attestation.PredicateType("https://in-toto.io/attestation/vulns/v0.2")
var PredicateType = PredicateTypeV2

// Parser is the vulnerability parser
type Parser struct{}

func New() *Parser {
	return &Parser{}
}

func (*Parser) SupportsType(predTypes ...string) bool {
	return slices.Contains(predTypes, string(PredicateType))
}

func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	// Try v02 and then v01
	var pred attestation.Predicate
	pred, err := parseV2(data)
	if err != nil {
		// proto: syntax error (line 1:2): invalid value
		return nil, fmt.Errorf("parsing predicate: %w", err)
	}

	return pred, nil
}

func parseV2(data []byte) (*generic.Predicate, error) {
	v2 := v02.Vulns{}
	if err := protojson.Unmarshal(data, &v2); err != nil {
		// Transform the error to our wrong type error
		if strings.Contains(err.Error(), "proto:") && strings.Contains(err.Error(), "syntax error") && strings.Contains(err.Error(), "invalid value") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("error parsing v02 vuln predicate: %s", err)
	}
	pred := &generic.Predicate{
		Type:   PredicateTypeV2,
		Parsed: &v2,
		Data:   data,
	}
	return pred, nil
}
