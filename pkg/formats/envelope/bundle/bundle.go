// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Packager bundle provides functionality to work with the sigstore budle
// format
package bundle

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/puerco/ampel/pkg/attestation"
	sigstore "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type Parser struct{}

// ParseFile parses a file and returns all envelopes in it.
func (p *Parser) ParseStream(r io.Reader) ([]attestation.Envelope, error) {
	var env = &Envelope{
		Bundle: sigstore.Bundle{},
	}

	// Parse
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("parsing stream: %w", err)
	}

	if err := protojson.Unmarshal(data, env); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("unmarshaling envelope: %w", err)
	}
	return []attestation.Envelope{env}, nil
}

func (p *Parser) ParseFile(path string) ([]attestation.Envelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	return p.ParseStream(f)
}

// FileExtensions returns the file extennsions this parser will look at.
func (p *Parser) FileExtensions() []string {
	return []string{"json"}
}
