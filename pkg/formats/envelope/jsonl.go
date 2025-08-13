// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/jsonl"
)

var _ attestation.EnvelopeParser = (*JsonlParser)(nil)

// JsonlParser is a virtual parser that splits the jsonl files into the contained
// JSON structs and calls the configured envelope parsers for each instance.
type JsonlParser struct{}

func NewJSONL() *JsonlParser {
	return &JsonlParser{}
}

// TODO(puerco): We need a way to parse the data to detect if it's in linear json.
// Until then, we cannot add the parser to the parsers list.

// ParseFile parses a file and returns all envelopes in it.
func (jlp *JsonlParser) ParseStream(jsonlStream io.Reader) ([]attestation.Envelope, error) {
	ret := []attestation.Envelope{}
	for i, r := range jsonl.IterateBundle(jsonlStream) {
		if r == nil {
			continue
		}
		att, err := Parsers.Parse(r)
		if err != nil {
			return nil, fmt.Errorf("error parsing struct #%d: %w", i, err)
		}
		ret = append(ret, att...)
	}
	return ret, nil
}

// ParseFile takes a path and returns the attestations in the file
func (jlp *JsonlParser) ParseFile(path string) ([]attestation.Envelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	return jlp.ParseStream(f)
}

func (jlp *JsonlParser) Parse(data []byte) ([]attestation.Envelope, error) {
	return jlp.ParseStream(bytes.NewReader(data))
}

// FileExtensions returns the file extennsions this parser will look at.
func (jlp *JsonlParser) FileExtensions() []string {
	return []string{"jsonl"}
}
