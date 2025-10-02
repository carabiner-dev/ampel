// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"errors"
	"fmt"
	"slices"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/signer/key"

	"github.com/carabiner-dev/ampel/pkg/context"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

var ResultsAttestationFormats = []string{
	"ampel", // Regular ampel resultSet
}

type VerificationOptions struct {
	// Embed the evaluator options
	options.EvaluatorOptions

	// Collectors is a collection of configured attestation fetchers
	Collectors []attestation.Fetcher

	// ContextProviders has a list of providers to read contextual data
	ContextProviders []context.Provider

	// AttestationFiles are additional attestations passed manually
	AttestationFiles []string

	// Attestations are preparsed attestations the policy evaluator receives
	// when called, usually preparsed by the PolicySet evaluator.
	Attestations []attestation.Envelope

	// DefaultEvaluator is the default evaluator we use when a policy does
	// not define one.
	DefaultEvaluator class.Class

	// AttestResults will generate an attestation of the evaluation results
	AttestResults bool

	// AttestFormat specifies the format used when AttestResults is true
	AttestFormat string

	// ResultsAttestationPath stores the path to write the results attestation
	ResultsAttestationPath string

	// SetExitCode sets a non-zero exit code on artifact verification
	SetExitCode bool

	// Policies to evaluate from a PolicySet. Default is to evaluate all.
	Policies []string

	// GitCommitShaHack enables a hack to duplicate gitCommit subjects of read
	// attestations as sha1 when reading attestations
	GitCommitShaHack bool

	// IdentityStrings feeds the signature identities to add to the policy
	// definitions when verifying signatures.
	IdentityStrings []string

	// Keys is a list of public key providers that will be used to verify signed
	// items. These keys will be supplied to verifiers when checking signatures of
	// signed stuff (ie DSSE envelopes). It is up to the policy to recognize any
	// of the matched keys as valid identities.
	//
	// Note that each signature will be verified against all keys loaded, so clients
	// are advised to load only those keys required for each policy evaluation.
	Keys []key.PublicKeyProvider

	// EnforceExpiration forces evaluations to fail when the policy or policy set
	// expiration date has passed. If no expiration date is set, this setting is ignored.
	EnforceExpiration bool

	// AllowEmptySetChains prevents the policy from failing if the chain selectors
	// don't return any mutated subjects.
	AllowEmptySetChains bool
}

// Validate checks the options set
func (opts *VerificationOptions) Validate() error {
	errs := []error{}
	if opts.AttestFormat != "" && !slices.Contains(ResultsAttestationFormats, opts.AttestFormat) {
		errs = append(errs, fmt.Errorf("invalid results attestation format: %q", opts.AttestFormat))
	}

	return errors.Join(errs...)
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

	// EnforceExpiration is on to check expiration dates by default
	EnforceExpiration: true,

	// AllowEmptySetChains is set to true. This means that if no subjects
	// result from the selectors, the set passes with the policies softfailed.
	AllowEmptySetChains: true,

	// By default, we attesta results in the ampel format
	AttestFormat: "ampel",
}

func NewVerificationOptions() VerificationOptions {
	return DefaultVerificationOptions
}

func (vo *VerificationOptions) WithContextProvider(provider context.Provider) *VerificationOptions {
	vo.ContextProviders = append(vo.ContextProviders, provider)
	return vo
}
