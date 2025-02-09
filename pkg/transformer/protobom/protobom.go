// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package protobom

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/cyclonedx"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/protobom"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/spdx"
	"github.com/protobom/protobom/pkg/reader"
	"google.golang.org/protobuf/encoding/protojson"
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
func (p *Transformer) Mutate(preds []attestation.Predicate) ([]attestation.Predicate, error) {
	r := reader.New()
	if len(preds) != 1 {
		return nil, fmt.Errorf("default tranformation requires exactly one predicate")
	}

	if !slices.Contains(PredicateTypes, preds[0].GetType()) {
		return nil, fmt.Errorf(
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
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("parsing data: %w", err)
	}
	bdata, err := protojson.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshaling rendered protobom predicate: %w", err)
	}
	// Reset the predicates
	return []attestation.Predicate{
		&generic.Predicate{
			Type:   protobom.PredicateType,
			Data:   bdata,
			Parsed: doc,
		},
	}, err
}

// func (p *Parser) SupportsType(testTypes ...string) bool {
// 	for _, pt := range PredicateTypes {
// 		if slices.Contains(testTypes, pt) {
// 			return true
// 		}
// 	}
// 	return false
// }
