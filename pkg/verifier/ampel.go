// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/collector"
	"github.com/carabiner-dev/ampel/pkg/evaluator"
	"github.com/carabiner-dev/ampel/pkg/oscal"
	"github.com/carabiner-dev/ampel/pkg/transformer"
)

// AmpelImplementation
type AmpelVerifier interface {
	GatherAttestations(context.Context, *VerificationOptions, attestation.Subject) ([]attestation.Envelope, error)
	ParseAttestations(context.Context, []string) ([]attestation.Envelope, error)
	BuildEvaluators(*VerificationOptions, *api.Policy) (map[evaluator.Class]evaluator.Evaluator, error)
	BuildTransformers(*VerificationOptions, *api.Policy) (map[transformer.Class]transformer.Transformer, error)
	Transform(*VerificationOptions, map[transformer.Class]transformer.Transformer, *api.Policy, []attestation.Predicate) ([]attestation.Predicate, error)
	CheckIdentities(*VerificationOptions, *api.Policy, []attestation.Envelope) (bool, error)
	FilterAttestations(*VerificationOptions, attestation.Subject, []attestation.Envelope) ([]attestation.Predicate, error)
	AssertResult(*api.Policy, *api.Result) error
	AttestResult(context.Context, *VerificationOptions, attestation.Subject, *api.Result) error
	VerifySubject(context.Context, *VerificationOptions, map[evaluator.Class]evaluator.Evaluator, *api.Policy, attestation.Subject, []attestation.Predicate) (*api.Result, error)
}

type AmpelStatusChecker interface {
	GatherResults(context.Context, *StatusOptions, attestation.Subject) ([]attestation.Envelope, error)
	ParseAttestedResults(context.Context, *StatusOptions, []attestation.Envelope) ([]attestation.Predicate, error)
	CheckIdentities(*StatusOptions, []attestation.Envelope) (bool, error)
	ComputeComplianceStatus(*oscal.Catalog, []attestation.Predicate) (*Status, error)
}

func New(opts ...fnOpt) (*Ampel, error) {
	ampel := &Ampel{
		impl:      &defaultIplementation{},
		checker:   &defaultStatusChecker{},
		Collector: collector.New(),
	}

	for _, opFn := range opts {
		if err := opFn(ampel); err != nil {
			return nil, err
		}
	}
	return ampel, nil
}

type fnOpt func(*Ampel) error

var WithCollector = func(init string) fnOpt {
	return func(ampel *Ampel) error {
		if err := ampel.Collector.AddRepositoryFromString(init); err != nil {
			return err
		}
		return nil
	}
}

var WithCollectors = func(init []string) fnOpt {
	return func(ampel *Ampel) error {
		for _, s := range init {
			if err := ampel.Collector.AddRepositoryFromString(s); err != nil {
				return err
			}
		}
		return nil
	}
}

// Ampel is the attestation verifier
type Ampel struct {
	impl      AmpelVerifier
	checker   AmpelStatusChecker
	Collector *collector.Agent
}
