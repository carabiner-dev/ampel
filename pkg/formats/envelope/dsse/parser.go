// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/statement"
)

// Parser for attestations wrapped in DSSE envelopes
type Parser struct {
}

// ParseFile parses a file and returns all envelopes in it.
func (p *Parser) ParseStream(r io.Reader) ([]attestation.Envelope, error) {
	env := Envelope{}
	dec := json.NewDecoder(r)
	if err := dec.Decode(&env); err != nil {
		return nil, err
	}

	// If there is no payload, then don't treat the envelope as DSSE
	if env.Payload == nil && len(env.Signatures) == 0 {
		return nil, attestation.ErrNotCorrectFormat
	}

	for _, s := range env.Envelope.Signatures {
		env.Signatures = append(env.Signatures, &Signature{
			KeyID:     s.GetKeyid(),
			Signature: s.GetSig(),
		})
	}

	// Parse the envelope payload
	s, err := statement.Parsers.Parse(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("error parsing the envelope payload: %w", err)
	}

	env.Statement = s
	return []attestation.Envelope{&env}, nil
}

// FileExtensions returns the file extennsions this parser will look at.
func (p *Parser) FileExtensions() []string {
	return []string{"json", "jsonl", "intoto"}
}
