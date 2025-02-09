// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package trivy

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
)

type Parser struct{}

var _ attestation.PredicateParser = (*Parser)(nil)

func New() *Parser {
	return &Parser{}
}

func (*Parser) SupportsType(predTypes ...string) bool {
	return slices.Contains(predTypes, string(PredicateType))
}

func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	var report = &TrivyReport{}
	if err := json.Unmarshal(data, report); err != nil {
		return nil, fmt.Errorf("unmarshalling trivy report: %w", err)
	}

	if report.SchemaVersion == 0 && report.CreatedAt == nil {
		return nil, attestation.ErrNotCorrectFormat
	}
	return &generic.Predicate{
		Type:   PredicateType,
		Parsed: report,
		Data:   data,
	}, nil
}
