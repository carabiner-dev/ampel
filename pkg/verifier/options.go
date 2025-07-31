// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/context"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

type VerificationOptions struct {
	// Embed the evaluator options
	options.EvaluatorOptions

	// Collectors is a collection of configured attestation fetchers
	Collectors []attestation.Fetcher

	// ContextProviders has a list of providers to read contextual data
	ContextProviders []context.Provider

	// AttestationFiles are additional attestations passed manually
	AttestationFiles []string

	// DefaultEvaluator is the default evaluator we use when a policy does
	// not define one.
	DefaultEvaluator class.Class

	// AttestResults will generate an attestation of the evaluation results
	AttestResults bool

	// ResultsAttestationPath stores the path to write the results attestation
	ResultsAttestationPath string

	// SetExitCode sets a non-zero exit code on artifact verification
	SetExitCode bool

	// Policies to evaluate from a PolicySet. Default is to evaluate all.
	Policies []string

	// GitCommitShaHack enables a hack to duplicate gitCommit subjects of read
	// attestations as sha1 when reading attestations
	GitCommitShaHack bool
}

var DefaultVerificationOptions = VerificationOptions{
	EvaluatorOptions: options.Default,

	// DefaultEvaluator the the default eval enfine is the lowest version
	// of CEL available
	DefaultEvaluator: class.Class("cel@v0"),

	// ResultsAttestationPath path to the results attestation
	ResultsAttestationPath: "results.intoto.json",

	// Duplicate any gitCommit digests as sha1
	GitCommitShaHack: true,

	// Context providers, by default we enable the envvar provider
	ContextProviders: []context.Provider{},
}

func NewVerificationOptions() VerificationOptions {
	return DefaultVerificationOptions
}

func (vo *VerificationOptions) WithContextProvider(provider context.Provider) *VerificationOptions {
	vo.ContextProviders = append(vo.ContextProviders, provider)
	return vo
}
