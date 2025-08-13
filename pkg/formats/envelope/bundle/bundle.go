// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Packager bundle provides functionality to work with the sigstore budle
// format
package bundle

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/hasher"
	intoto "github.com/in-toto/attestation/go/v1"
	sigstore "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type Parser struct{}

// ParseFile parses a file and returns all envelopes in it.
func (p *Parser) ParseStream(r io.Reader) ([]attestation.Envelope, error) {
	// Read all data to memory :/
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("parsing stream: %w", err)
	}

	return p.Parse(data)
}

// ParseFile parses a sigstore bundle and returns the envelope
func (p *Parser) ParseFile(path string) ([]attestation.Envelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	envs, err := p.ParseStream(f)
	if err != nil {
		return nil, err
	}

	// Set the source data in the envelope
	src := envs[0].GetStatement().GetPredicate().GetOrigin()
	rd, ok := src.(*intoto.ResourceDescriptor)
	if rd != nil && !ok {
		return nil, errors.New("unable to cast source as resource descriptor")
	}

	if rd != nil {
		rd.Name = filepath.Base(path)
		rd.Uri = fmt.Sprintf("file:%s", path)
		envs[0].GetStatement().GetPredicate().SetOrigin(rd)
	}
	return envs, nil
}

func (p *Parser) Parse(data []byte) ([]attestation.Envelope, error) {
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

	digests, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(data)})
	if err != nil || len(*digests) == 0 {
		return nil, fmt.Errorf("error hashing envelope data: %w", err)
	}

	// Reigster the attestation digests in its source
	env.GetStatement().GetPredicate().SetOrigin(digests.ToResourceDescriptors()[0])

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
