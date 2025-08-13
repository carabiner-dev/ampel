// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package statement

import (
	"errors"
	"fmt"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/sirupsen/logrus"

	"github.com/carabiner-dev/ampel/pkg/formats/statement/intoto"
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
		pres, err := p.Parse(data)
		if err == nil {
			logrus.Debugf("Checking if statement is: %s [YES]", f)
			return pres, nil
		}

		if strings.Contains(err.Error(), attestation.ErrNotCorrectFormat.Error()) {
			logrus.Debugf("Checking if statement is: %s [ERROR]", f)
			errs = append(errs, err)
			continue
		}
		logrus.Debugf("Checking if statement is: %s [NO]", f)
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("unknown statement type: %w", attestation.ErrNotCorrectFormat)
	}
	return nil, errors.Join(errs...)
}
