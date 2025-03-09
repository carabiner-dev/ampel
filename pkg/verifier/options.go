// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

type VerificationOptions struct {
	// Embed the evaluator options
	options.EvaluatorOptions

	// Collectors is a collection of configured attestation fetchers
	Collectors []attestation.Fetcher

	// AttestationFiles are additional attestations passed manually
	AttestationFiles []string

	// DefaultEvaluator is the default evaluator we use when a policy does
	// not define one.
	DefaultEvaluator class.Class

	// AttestResults will generate an attestation of the evaluation results
	AttestResults bool

	// ResultsAttestationPath stores the path to write the results attestation
	ResultsAttestationPath string
}

var DefaultVerificationOptions = VerificationOptions{
	EvaluatorOptions: options.EvaluatorOptions{
		Context: &api.Context{},
	},

	// DefaultEvaluator the the default eval enfine is the lowest version
	// of CEL available
	DefaultEvaluator: class.Class("cel@v1.0.0"),

	// ResultsAttestationPath path to the results attestation
	ResultsAttestationPath: "results.intoto.json",
}

func NewVerificationOptions() VerificationOptions {
	return DefaultVerificationOptions
}
