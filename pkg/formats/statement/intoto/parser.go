// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package intoto

import (
	"encoding/json"
	"fmt"
	"strings"

	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate"
)

type Parser struct{}

func (p *Parser) Parse(b []byte) (attestation.Statement, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty statement data when attempting to parse")
	}
	stmt := Statement{
		Predicate: nil,
		Statement: v1.Statement{},
	}

	// Decode the statement data
	if err := json.Unmarshal(b, &stmt); err != nil {
		if strings.Contains(err.Error(), "json: unknown field") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("decoding statement json: %w", err)
	}

	// Check if we got somethign meaningful
	if stmt.Predicate == nil && len(stmt.Subject) == 0 {
		return nil, attestation.ErrNotCorrectFormat
	}

	pdata, err := stmt.Statement.Predicate.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate data to JSON: %w", err)
	}
	pred, err := predicate.Parsers.Parse(pdata)
	if err != nil {
		return nil, fmt.Errorf("parsing predicate: %w", err)
	}

	stmt.Predicate = pred

	return &stmt, nil
}
