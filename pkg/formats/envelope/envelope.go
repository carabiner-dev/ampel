// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/envelope/bare"
	"github.com/carabiner-dev/ampel/pkg/formats/envelope/bundle"
	"github.com/carabiner-dev/ampel/pkg/formats/envelope/dsse"
	"github.com/sirupsen/logrus"
)

type Format string

const (
	FormatDSSE     Format = "dsse"
	FormatBare     Format = "bare"
	FormatBundleV3 Format = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

// ParserList wraps a map listing the loaded parsers to expose convenience methods
type ParserList map[Format]attestation.EnvelopeParser

var Parsers = ParserList{
	FormatDSSE:     &dsse.Parser{},
	FormatBundleV3: &bundle.Parser{},
}

// Parse takes a reader and parses
func (list *ParserList) Parse(r io.Reader) ([]attestation.Envelope, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading atetstation data: %w", err)
	}
	for f, parser := range *list {
		logrus.Debugf("Checking if envelope is %s", f)
		env, err := parser.ParseStream(bytes.NewReader(data))
		if err == nil {
			logrus.Debugf("Found envelope type: %s ", f)
			return env, nil
		}
		if !errors.Is(err, attestation.ErrNotCorrectFormat) {
			return nil, err
		}
	}

	// If we're here, then we treat the file as a bare attestation
	env, err := bare.New().ParseStream(bytes.NewReader(data))
	if err == nil {
		logrus.Debug("Parsing statement as bare JSON")
		return env, nil
	}

	return nil, attestation.ErrNotCorrectFormat
}
