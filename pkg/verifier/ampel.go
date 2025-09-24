// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"errors"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector"

	"github.com/carabiner-dev/ampel/pkg/oscal"
)

var ErrMissingAttestations = errors.New("required attestations missing to verify subject")

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
