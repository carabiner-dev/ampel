// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"io"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/collector"
	"github.com/carabiner-dev/ampel/pkg/evaluator"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/oscal"
	"github.com/carabiner-dev/ampel/pkg/transformer"
)

// AmpelImplementation
type AmpelVerifier interface {
	GatherAttestations(context.Context, *VerificationOptions, *collector.Agent, *api.Policy, attestation.Subject, []attestation.Envelope) ([]attestation.Envelope, error)
	ParseAttestations(context.Context, []string) ([]attestation.Envelope, error)
	BuildEvaluators(*VerificationOptions, *api.Policy) (map[class.Class]evaluator.Evaluator, error)
	BuildTransformers(*VerificationOptions, *api.Policy) (map[transformer.Class]transformer.Transformer, error)
	Transform(*VerificationOptions, map[transformer.Class]transformer.Transformer, *api.Policy, attestation.Subject, []attestation.Predicate) (attestation.Subject, []attestation.Predicate, error)
	CheckIdentities(*VerificationOptions, []*api.Identity, []attestation.Envelope) (bool, error)
	FilterAttestations(*VerificationOptions, attestation.Subject, []attestation.Envelope) ([]attestation.Predicate, error)
	AssertResult(*api.Policy, *api.Result) error
	AttestResult(context.Context, *VerificationOptions, *api.Result) error

	// AttestResultToWriter takes an evaluation result and writes an attestation to the supplied io.Writer
	AttestResultToWriter(io.Writer, *api.Result) error

	// AttestResultSetToWriter takes an policy resultset and writes an attestation to the supplied io.Writer
	AttestResultSetToWriter(io.Writer, *api.ResultSet) error

	VerifySubject(context.Context, *VerificationOptions, map[class.Class]evaluator.Evaluator, *api.Policy, attestation.Subject, []attestation.Predicate) (*api.Result, error)
	// ProcessChainedSubjects proceses the chain of attestations to find the ultimate
	// subject a policy is supposed to operate on
	ProcessChainedSubjects(context.Context, *VerificationOptions, map[class.Class]evaluator.Evaluator, *collector.Agent, *api.Policy, attestation.Subject, []attestation.Envelope) (attestation.Subject, []*api.ChainedSubject, bool, error)
}

type AmpelStatusChecker interface {
	GatherResults(context.Context, *StatusOptions, attestation.Subject) ([]attestation.Envelope, error)
	ParseAttestedResults(context.Context, *StatusOptions, []attestation.Envelope) ([]attestation.Predicate, error)
	CheckIdentities(*StatusOptions, []attestation.Envelope) (bool, error)
	ComputeComplianceStatus(*oscal.Catalog, []attestation.Predicate) (*Status, error)
}

func New(opts ...fnOpt) (*Ampel, error) {
	agent, err := collector.New()
	if err != nil {
		return nil, err
	}
	ampel := &Ampel{
		impl:      &defaultIplementation{},
		checker:   &defaultStatusChecker{},
		Collector: agent,
	}

	for _, opFn := range opts {
		if err := opFn(ampel); err != nil {
			return nil, err
		}
	}
	return ampel, nil
}

type fnOpt func(*Ampel) error

var WithCollector = func(repository attestation.Repository) fnOpt {
	return func(a *Ampel) error {
		return a.Collector.AddRepository(repository)
	}
}

var WithCollectors = func(repos []attestation.Repository) fnOpt {
	return func(a *Ampel) error {
		return a.Collector.AddRepository(repos...)
	}
}

// WithCollectorInit adds a collector from an init string
var WithCollectorInit = func(init string) fnOpt {
	return func(ampel *Ampel) error {
		if err := ampel.Collector.AddRepositoryFromString(init); err != nil {
			return err
		}
		return nil
	}
}

// WithCollectorInit adds multiple collectors from a list of init strings
var WithCollectorInits = func(init []string) fnOpt {
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
