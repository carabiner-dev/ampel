// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Packager bundle provides functionality to work with the sigstore budle
// format
package bundle

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	sigstore "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"

	//	intoto "github.com/in-toto/attestation/go/v1"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/hasher"
)

type Parser struct{}

// ParseFile parses a file and returns all envelopes in it.
func (p *Parser) ParseStream(r io.Reader) ([]attestation.Envelope, error) {
	// Readd all data to mem :/
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("parsing stream: %w", err)
	}

	return p.Parse(data)
}

func (p *Parser) ParseFile(path string) ([]attestation.Envelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	return p.ParseStream(f)
}

func (p *Parser) Parse(data []byte) ([]attestation.Envelope, error) {
	digests, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(data)})
	if err != nil || len(*digests) == 0 {
		return nil, fmt.Errorf("error hashing envelope data: %w", err)
	}

	env := &Envelope{
		Bundle: sigstore.Bundle{},
	}

	if err := p.unmarshalTo(env, data); err != nil {
		return nil, err
	}

	// Ensure we have a valid statement and predicate
	if _, err := env.GetStatementOrErr(); err != nil {
		return nil, err
	}

	// Reigster the attestation digests in its source
	env.GetStatement().GetPredicate().SetSource(digests.ToResourceDescriptors()[0])

	return []attestation.Envelope{env}, nil
}

func (p *Parser) unmarshalTo(env *Envelope, data []byte) error {
	if err := protojson.Unmarshal(data, &env.Bundle); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return attestation.ErrNotCorrectFormat
		}
		return fmt.Errorf("unmarshalling bundle: %w", err)
	}
	return nil
}

// FileExtensions returns the file extennsions this parser will look at.
func (p *Parser) FileExtensions() []string {
	return []string{"json"}
}
