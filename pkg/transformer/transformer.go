// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package transformer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/transformer/protobom"
	"github.com/carabiner-dev/ampel/pkg/transformer/vex"
	"github.com/carabiner-dev/ampel/pkg/transformer/vulnreport"
)

// Ensure the loaded drivers implement the transformers interface
var (
	_ Transformer = (*protobom.Transformer)(nil)
	_ Transformer = (*vulnreport.Transformer)(nil)
)

// Factory returns a list of transformers from
// a list of string identifiers
type Factory struct{}

// Get returns
func (tf *Factory) Get(c Class) (Transformer, error) {
	if !strings.HasPrefix(c.Name(), "internal:") {
		return nil, errors.New("only internal transformers are supported for now")
	}

	s := strings.TrimPrefix(c.Name(), "internal:")
	switch s {
	case protobom.ClassName:
		logrus.Debugf("Found driver for transformer class %s", s)
		return protobom.New(), nil
	case vulnreport.ClassName:
		logrus.Debugf("Found driver for transformer class %s", s)
		return protobom.New(), nil
	case vex.ClassName:
		logrus.Debugf("Found driver for transformer class %s", s)
		return vex.New(), nil
	default:
		return nil, fmt.Errorf("unknown transformer %q", s)
	}
}

// Transformer is an interface that models a predicate transformer
type Transformer interface {
	Mutate(attestation.Subject, []attestation.Predicate) (attestation.Subject, []attestation.Predicate, error)
}

type Info struct {
	Identifier string
	Version    string
	Hashes     map[string]string
}

// InputRecord records the inputs that went into a predicate
// transformation process.
type InputRecord struct {
	Type     attestation.PredicateType
	Subjects attestation.Subject
	Hashes   map[string]string
}

// OutputRecord is a struct that catpures metadata about
// the outputs resulting from a tranformer run.
type OutputRecord struct {
	Hashes map[string]string
	Type   attestation.PredicateType
}

// Record is a struct that records a run
// of a transformer.
type Record struct {
	Date        *time.Time
	Transformer Info
	Inputs      []InputRecord
	Output      []OutputRecord
}
