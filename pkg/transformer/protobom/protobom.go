// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package protobom

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/protobom/protobom/pkg/reader"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/collector/predicate/cyclonedx"
	"github.com/carabiner-dev/collector/predicate/generic"
	"github.com/carabiner-dev/collector/predicate/protobom"
	"github.com/carabiner-dev/collector/predicate/spdx"
)

type Transformer struct{}

var ClassName = "protobom"

func New() *Transformer {
	return &Transformer{}
}

// PredicateTypes
var PredicateTypes = []attestation.PredicateType{
	spdx.PredicateType,
	cyclonedx.PredicateType,
}

// Transformer generates a protobom predicate from any of the supported SBOM
// formats.
func (p *Transformer) Mutate(_ attestation.Subject, preds []attestation.Predicate) (attestation.Subject, []attestation.Predicate, error) {
	r := reader.New()
	if len(preds) != 1 {
		return nil, nil, fmt.Errorf("default tranformation requires exactly one predicate")
	}

	if !slices.Contains(PredicateTypes, preds[0].GetType()) {
		return nil, nil, fmt.Errorf(
			"predicate type not supported, must be one of %v (got %s)",
			PredicateTypes, preds[0].GetType(),
		)
	}

	s := bytes.NewReader(preds[0].GetData())
	doc, err := r.ParseStream(s)
	if err != nil {
		// If it's not a supported SBOM format, catch the error and
		// return the common error to hand off to another predicate parser.
		if strings.Contains(err.Error(), "unknown SBOM format") {
			return nil, nil, attestation.ErrNotCorrectFormat
		}
		return nil, nil, fmt.Errorf("parsing data: %w", err)
	}
	bdata, err := protojson.Marshal(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling rendered protobom predicate: %w", err)
	}
	// Reset the new predicates
	return nil, []attestation.Predicate{
		&generic.Predicate{
			Type:   protobom.PredicateType,
			Data:   bdata,
			Parsed: doc,
		},
	}, err
}
