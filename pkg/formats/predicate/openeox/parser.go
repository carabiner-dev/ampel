// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package openeox

import (
	"fmt"
	"slices"
	"strings"

	"github.com/carabiner-dev/openeox"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
)

var PredicateType = attestation.PredicateType("https://docs.oasis-open.org/openeox/v1.0")

type Parser struct{}

func New() *Parser {
	return &Parser{}
}

func (*Parser) SupportsType(predTypes ...attestation.PredicateType) bool {
	return slices.Contains(predTypes, PredicateType)
}

func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	parser, err := openeox.NewParser()
	if err != nil {
		return nil, fmt.Errorf("creating openeox parser: %w", err)
	}

	shell, err := parser.ParseShell(data)
	if err != nil {
		if strings.Contains(err.Error(), "proto:") && strings.Contains(err.Error(), "unknown field") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("parsing data: %w", err)
	}

	return &generic.Predicate{
		Type:   PredicateType,
		Parsed: shell,
		Data:   data,
	}, nil
}
