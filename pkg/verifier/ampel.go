// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"errors"
	"fmt"

	api "github.com/puerco/ampel/pkg/api/v1"
	v1 "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/evaluator"
	"github.com/puerco/ampel/pkg/transformer"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AmpelImplementation
type AmpelImplementation interface {
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

func New() (*Ampel, error) {
	return &Ampel{
		impl: &defaultIplementation{},
	}, nil
}

// Ampel is the attestation verifier
type Ampel struct {
	impl AmpelImplementation
}

// Verify checks a subject against a policy using the available evidence
func (ampel *Ampel) Verify(
	ctx context.Context, opts *VerificationOptions, policy any, subject attestation.Subject,
) (*api.ResultSet, error) {
	switch v := policy.(type) {
	case *api.Policy:
		res, err := ampel.VerifySubjectWithPolicy(ctx, opts, v, subject)
		if err != nil {
			return nil, err
		}
		return &v1.ResultSet{Results: []*v1.Result{res}}, nil
	case *api.PolicySet:
		var rs = &v1.ResultSet{}
		for i, p := range v.Policies {
			res, err := ampel.VerifySubjectWithPolicy(ctx, opts, p, subject)
			if err != nil {
				return nil, fmt.Errorf("evaluating policy #%d: %w", i, err)
			}
			rs.Results = append(rs.Results, res)
		}
		return rs, nil
	default:
		return nil, fmt.Errorf("did not get a poicy or policy set")
	}
}

// VerifySubjectWithPolicy verifies a subject against a single policy
func (ampel *Ampel) VerifySubjectWithPolicy(
	ctx context.Context, opts *VerificationOptions, policy *api.Policy, subject attestation.Subject,
) (*api.Result, error) {
	// Fetch applicable evidence
	atts, err := ampel.impl.GatherAttestations(ctx, opts, subject)
	if err != nil {
		return nil, fmt.Errorf("gathering evidence: %w", err)
	}

	// Parse any extra files defined in the options
	moreatts, err := ampel.impl.ParseAttestations(ctx, opts.AttestationFiles)
	if err != nil {
		return nil, fmt.Errorf("parsing files: %w", err)
	}
	atts = append(atts, moreatts...)

	// Here, the policy may not require attestations (noop) but it's a corner
	// case, we'll fix it later.
	if len(atts) == 0 {
		return nil, errors.New("no evidence found to evaluate policy")
	}

	// Check identities to see if the attestations can be admitted
	// TODO(puerco)
	// Option: Unmatched identities cause a:fail or b:ignore
	allow, err := ampel.impl.CheckIdentities(opts, policy, atts)
	if err != nil {
		return nil, fmt.Errorf("admission failed: %w", err)
	}

	if !allow {
		return &api.Result{
			Status:      "FAIL",
			DateStart:   timestamppb.Now(),
			DateEnd:     timestamppb.Now(),
			Policy:      &api.PolicyRef{},
			EvalResults: []*api.EvalResult{},
		}, nil
	}

	// Filter attestations to those applicable to the subject
	preds, err := ampel.impl.FilterAttestations(opts, subject, atts)
	if err != nil {
		return nil, fmt.Errorf("filtering attestations: %w", err)
	}

	transformers, err := ampel.impl.BuildTransformers(opts, policy)
	if err != nil {
		return nil, fmt.Errorf("building policy transformers: %w", err)
	}

	// Apply the defined tranformations to the predicates
	preds, err = ampel.impl.Transform(opts, transformers, policy, preds)
	if err != nil {
		return nil, fmt.Errorf("applying transformations: %w", err)
	}

	// Build the required evaluators
	evaluators, err := ampel.impl.BuildEvaluators(opts, policy)
	if err != nil {
		return nil, fmt.Errorf("building evaluators: %w", err)
	}

	// Eval Policy
	result, err := ampel.impl.VerifySubject(ctx, opts, evaluators, policy, subject, preds)
	if err != nil {
		return nil, fmt.Errorf("verifying subject: %w", err)
	}

	// Assert the status from the evaluation results
	if err := ampel.impl.AssertResult(policy, result); err != nil {
		return nil, fmt.Errorf("asserting results: %w", err)
	}

	// Generate the results attestation. If the attestation is disabled in the
	// options, this is a NOOP.
	if err := ampel.impl.AttestResult(ctx, opts, subject, result); err != nil {
		return nil, fmt.Errorf("attesting results: %w", err)
	}

	// Generate outputs
	return result, nil
}
