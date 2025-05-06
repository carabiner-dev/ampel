// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
)

type PolicyError struct {
	error
	Guidance string
}

// Verify checks a subject against a policy using the available evidence
func (ampel *Ampel) Verify(
	ctx context.Context, opts *VerificationOptions, policy any, subject attestation.Subject,
) (*api.ResultSet, error) {
	switch v := policy.(type) {
	case *api.Policy:
		if len(opts.Policies) > 0 && !slices.Contains(opts.Policies, v.Id) {
			return &api.ResultSet{}, nil
		}
		res, err := ampel.VerifySubjectWithPolicy(ctx, opts, v, subject)
		if err != nil {
			return nil, err
		}
		return &api.ResultSet{Results: []*api.Result{res}}, nil
	case *api.PolicySet:
		rs := &api.ResultSet{
			Id:        v.Id,
			Meta:      v.Meta,
			DateStart: timestamppb.Now(),
			Subject: &api.ResourceDescriptor{
				Name:   subject.GetName(),
				Uri:    subject.GetUri(),
				Digest: subject.GetDigest(),
			},
			Results: []*api.Result{},
		}
		for i, p := range v.Policies {
			if len(opts.Policies) > 0 && !slices.Contains(opts.Policies, p.Id) {
				continue
			}
			res, err := ampel.VerifySubjectWithPolicy(ctx, opts, p, subject)
			if err != nil {
				return nil, fmt.Errorf("evaluating policy #%d: %w", i, err)
			}
			rs.Results = append(rs.Results, res)
		}
		if err := rs.Assert(); err != nil {
			return nil, fmt.Errorf("asserting ResultSet: %w", err)
		}
		return rs, nil
	case []*api.PolicySet:
		rs := &api.ResultSet{}
		for j, ps := range v {
			for i, p := range ps.Policies {
				if len(opts.Policies) > 0 && !slices.Contains(opts.Policies, p.Id) {
					continue
				}
				res, err := ampel.VerifySubjectWithPolicy(ctx, opts, p, subject)
				if err != nil {
					return nil, fmt.Errorf("evaluating policy #%d/%d: %w", j, i, err)
				}
				rs.Results = append(rs.Results, res)
			}
		}
		return rs, nil
	default:
		return nil, fmt.Errorf("did not get a policy or policy set")
	}
}

// VerifySubjectWithPolicy verifies a subject against a single policy
func (ampel *Ampel) VerifySubjectWithPolicy(
	ctx context.Context, opts *VerificationOptions, policy *api.Policy, subject attestation.Subject,
) (*api.Result, error) {
	// Build the required evaluators
	evaluators, err := ampel.impl.BuildEvaluators(opts, policy)
	if err != nil {
		return nil, fmt.Errorf("building evaluators: %w", err)
	}

	// Parse any extra attestation files defined in the options
	atts, err := ampel.impl.ParseAttestations(ctx, opts.AttestationFiles)
	if err != nil {
		return nil, fmt.Errorf("parsing files: %w", err)
	}

	// Process chained subjects. These have access to all the read attestations
	// even when some will be discarded in the next step. Computing the chain
	// will use the configured repositories if more attestations are required.
	var chain []*api.ChainedSubject
	subject, chain, policyFail, err := ampel.impl.ProcessChainedSubjects(ctx, opts, evaluators, ampel.Collector, policy, subject, atts)
	if err != nil {
		// If policyFail is true, then we don't return an error but rather
		// a policy fail result based on the error
		if policyFail {
			return failPolicyWithError(policy, chain, subject, err), nil
		}
		return nil, fmt.Errorf("processing chained subject: %w", err)
	}

	// Now that we have the right subject from the chain, gather all the
	// required attestations. Note that this will filter out any from the
	// command line that don't match the the new subject under test as
	// determined from the chain resolution.
	atts, err = ampel.impl.GatherAttestations(ctx, opts, ampel.Collector, policy, subject, atts)
	if err != nil {
		return nil, fmt.Errorf("gathering evidence: %w", err)
	}

	// Here, the policy may not require attestations (noop) but it's a corner
	// case, we'll fix it later.
	if len(atts) == 0 {
		return failPolicyWithError(
			policy, chain, subject,
			errors.New("no attestations found to evaluate policy"),
		), nil
	}

	// Check identities to see if the attestations can be admitted
	// TODO(puerco)
	// Option: Unmatched identities cause a:fail or b:ignore
	allow, err := ampel.impl.CheckIdentities(opts, policy.Identities, atts)
	if err != nil {
		return nil, fmt.Errorf("admission failed: %w", err)
	}

	if !allow {
		return failPolicyWithError(policy, chain, subject, PolicyError{
			error:    errors.New("identity validation failed"),
			Guidance: "Ensure the attestations are signed with the expected identites as defined in the policy.",
		}), nil
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

	// Apply the defined tranformations to the subject and predicates
	subject, preds, err = ampel.impl.Transform(opts, transformers, policy, subject, preds)
	if err != nil {
		return nil, fmt.Errorf("applying transformations: %w", err)
	}

	// Eval Policy
	result, err := ampel.impl.VerifySubject(ctx, opts, evaluators, policy, subject, preds)
	if err != nil {
		return nil, fmt.Errorf("verifying subject: %w", err)
	}

	result.Chain = chain

	// Assert the status from the evaluation results
	if err := ampel.impl.AssertResult(policy, result); err != nil {
		return nil, fmt.Errorf("asserting results: %w", err)
	}

	// Generate the results attestation. If the attestation is disabled in the
	// options, this is a NOOP.
	if err := ampel.impl.AttestResult(ctx, opts, result); err != nil {
		return nil, fmt.Errorf("attesting results: %w", err)
	}

	// Generate outputs
	return result, nil
}

// AttestResult writes an attestation capturing an evaluation result
func (ampel *Ampel) AttestResult(w io.Writer, result *api.Result) error {
	return ampel.impl.AttestResultToWriter(w, result)
}

// AttestResult writes an attestation capturing an evaluation result
func (ampel *Ampel) AttestResultSet(w io.Writer, resultset *api.ResultSet) error {
	return ampel.impl.AttestResultSetToWriter(w, resultset)
}

// failPolicyWithError returns a failed status result for the policicy where all
// tennets are failed with error err. If err is a `PolicyError` then the result
// error guidance for the tenets will be read from it.
func failPolicyWithError(p *api.Policy, chain []*api.ChainedSubject, subject attestation.Subject, err error) *api.Result {
	res := &api.Result{
		Status:      api.StatusFAIL,
		DateStart:   timestamppb.Now(),
		DateEnd:     timestamppb.Now(),
		Policy:      &api.PolicyRef{},
		EvalResults: []*api.EvalResult{},
		Meta:        p.GetMeta(),
		Chain:       chain,
		Subject:     api.NewResourceDescriptor().FromSubject(subject),
	}

	guidance := ""
	//nolint:errorlint
	if pe, ok := err.(PolicyError); ok {
		guidance = pe.Guidance
	}
	for _, t := range p.Tenets {
		er := &api.EvalResult{
			Id:         t.Id,
			Status:     api.StatusFAIL,
			Date:       timestamppb.Now(),
			Output:     nil,
			Statements: nil, // Or do we define it?
			Error: &api.Error{
				Message:  err.Error(),
				Guidance: guidance,
			},
			Assessment: nil,
		}
		res.EvalResults = append(res.EvalResults, er)
	}
	return res
}
