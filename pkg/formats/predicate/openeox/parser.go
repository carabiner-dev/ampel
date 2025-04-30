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

var (
	PredicateTypeShell = attestation.PredicateType("https://docs.oasis-open.org/openeox/shell/v1.0")
	PredicateTypeCore  = attestation.PredicateType("https://docs.oasis-open.org/openeox/core/v1.0")
)

type Parser struct{}

func New() *Parser {
	return &Parser{}
}

func (*Parser) SupportsType(predTypes ...attestation.PredicateType) bool {
	return slices.Contains(predTypes, PredicateTypeShell) || slices.Contains(predTypes, PredicateTypeCore)
}

// Parse reads a byte slice with an OpenEoX shell or core and returns an attestation
// predicate with the appropriate predicate type.
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	parser, err := openeox.NewParser()
	if err != nil {
		return nil, fmt.Errorf("creating openeox parser: %w", err)
	}

	isShell := true
	shell, err := parser.ParseShell(data)
	if err != nil {
		if strings.Contains(err.Error(), "proto:") && strings.Contains(err.Error(), "unknown field") {
			isShell = false
		} else {
			return nil, fmt.Errorf("parsing data: %w", err)
		}
	}

	if isShell {
		return &generic.Predicate{
			Type:   PredicateTypeShell,
			Parsed: shell,
			Data:   data,
		}, nil
	}

	// If its not a shell, it should be a direct core
	core, err := parser.ParseCore(data)
	if err != nil {
		if strings.Contains(err.Error(), "proto:") && strings.Contains(err.Error(), "unknown field") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("parsing data: %w", err)
	}

	return &generic.Predicate{
		Type:   PredicateTypeCore,
		Parsed: core,
		Data:   data,
	}, nil
}
