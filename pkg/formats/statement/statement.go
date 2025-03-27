// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package statement

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/statement/intoto"
	"github.com/sirupsen/logrus"
)

type Format string

const (
	FormatInToto Format = "intoto"
)

type ParserList map[Format]attestation.StatementParser

// Parsers
var Parsers = ParserList{
	FormatInToto: &intoto.Parser{},
}

// Parse attempts to parse the statement data using the known predicate drivers
func (pl *ParserList) Parse(data []byte) (attestation.Statement, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty statement data when attempting to parse")
	}
	errs := []error{}
	for f, p := range *pl {
		logrus.Debugf("Checking if statement is %s", f)
		pres, err := p.Parse(data)
		if err == nil {
			logrus.Debugf("found statement of type %s", f)
			return pres, nil
		}
		if !errors.Is(err, attestation.ErrNotCorrectFormat) {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("unknown statement type: %w", attestation.ErrNotCorrectFormat)
	}
	return nil, errors.Join(errs...)
}
