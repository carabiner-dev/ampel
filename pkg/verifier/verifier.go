// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/carabiner-dev/attestation"
	papi "github.com/carabiner-dev/policy/api/v1"
	gointoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/carabiner-dev/ampel/pkg/evaluator"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/evalcontext"
)

type PolicyError struct {
	error
	Guidance string
}

// Verify checks a subject against a policy using the available evidence
func (ampel *Ampel) Verify(
	ctx context.Context, opts *VerificationOptions, policy any, subject attestation.Subject,
) (papi.Results, error) {
	switch v := policy.(type) {
	case *papi.Policy:
		if len(opts.Policies) > 0 && !slices.Contains(opts.Policies, v.Id) {
			return &papi.ResultSet{}, nil
		}
		res, err := ampel.VerifySubjectWithPolicy(ctx, opts, v, subject)
		if err != nil {
			return nil, err
		}
		return res, nil
	case *papi.PolicySet:
		rs, err := ampel.VerifySubjectWithPolicySet(ctx, opts, v, subject)
		if err != nil {
			return nil, fmt.Errorf("evaluating policy set: %w", err)
		}
		return rs, nil
	case []*papi.PolicySet:
		rs := &papi.ResultSet{}
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

// VerifySubjectWithPolicySet runs a subject through a policy set.
func (ampel *Ampel) VerifySubjectWithPolicySet(
	ctx context.Context, opts *VerificationOptions, policySet *papi.PolicySet, subject attestation.Subject,
) (*papi.ResultSet, error) {
	// This is the resultSet to be returned
	resultSet := &papi.ResultSet{
		Id:        policySet.GetId(),
		Meta:      policySet.GetMeta(),
		DateStart: timestamppb.Now(),
		Subject: &gointoto.ResourceDescriptor{
			Name:   subject.GetName(),
			Uri:    subject.GetUri(),
			Digest: subject.GetDigest(),
		},
		Results: []*papi.Result{},
	}

	// Check if the policy is viable before
	if err := ampel.impl.CheckPolicySet(ctx, opts, policySet); err != nil {
		// If the policy failed validation, don't err. Fail the policy
		perr := PolicyError{}
		if errors.As(err, &perr) {
			return failPolicySetWithError(resultSet, perr), nil
		}
		// ..else something broke
		return nil, fmt.Errorf("checking policy: %w", err)
	}

	// Build the required evaluators
	evaluators := map[class.Class]evaluator.Evaluator{}
	// TODO(puerco): We should BuildEvaluators to get the already built evaluators
	for _, p := range policySet.Policies {
		policyEvals, err := ampel.impl.BuildEvaluators(opts, p)
		if err != nil {
			return nil, fmt.Errorf("building evaluators: %w", err)
		}
		maps.Insert(evaluators, maps.All(policyEvals))
	}

	// Parse any extra attestation files defined in the options
	atts, err := ampel.impl.ParseAttestations(ctx, opts.AttestationFiles)
	if err != nil {
		return nil, fmt.Errorf("parsing single attestations: %w", err)
	}

	// Add the (eval) context, to the (go) context :P
	evalContext, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if !ok {
		evalContext = evalcontext.EvaluationContext{}
	}

	// If the policy set has an eval context definition, then parse it and add
	// it to the the Go context payload
	if policySet.GetCommon() != nil && policySet.GetCommon().GetContext() != nil {
		var ok bool
		evalContext, ok = ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
		if !ok {
			evalContext = evalcontext.EvaluationContext{}
		}
		evalContext.Context = policySet.GetCommon().GetContext()
	}

	// Build the context to pass to the policy evaluations
	ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalContext)

	// Here we build the context that will be common for all policies as defined
	// in the policy set.
	evalContextValues, err := ampel.impl.AssembleEvalContextValues(ctx, opts, policySet.Common.Context)
	if err != nil {
		return nil, fmt.Errorf("assembling policy context: %w", err)
	}

	// Process policySet chain
	subjects, chain, policyFail, err := ampel.impl.ProcessPolicySetChainedSubjects(
		ctx, opts, evaluators, ampel.Collector, policySet, evalContextValues, subject, atts,
	)
	if err != nil {
		// If policyFail is true, then we don't return an error but rather
		// a policy fail result based on the error
		if policyFail {
			return failPolicySetWithError(resultSet, err), nil
		}
		return nil, fmt.Errorf("processing chained subject: %w", err)
	}

	evalContext.ChainedSubjects = chain

	// Rebuild the go context as we are now shipping the chained subjects.
	ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalContext)

	// Now cycle each policy....
	for i, pcy := range policySet.GetPolicies() {
		// ... and evaluate against each subject
		for _, subsubject := range subjects {
			res, err := ampel.VerifySubjectWithPolicy(ctx, opts, pcy, subsubject)
			if err != nil {
				return nil, fmt.Errorf("evaluating policy #%d: %w", i, err)
			}
			resultSet.Results = append(resultSet.Results, res)
		}
	}

	resultSet.DateEnd = timestamppb.Now()

	// Assert the policy set
	if err := resultSet.Assert(); err != nil {
		return nil, fmt.Errorf("asserting ResultSet: %w", err)
	}

	// Succcess!
	return resultSet, nil
}

// VerifySubjectWithPolicy verifies a subject against a single policy
func (ampel *Ampel) VerifySubjectWithPolicy(
	ctx context.Context, opts *VerificationOptions, policy *papi.Policy, subject attestation.Subject,
) (*papi.Result, error) {
	// Check if the policy is viable before
	if err := ampel.impl.CheckPolicy(ctx, opts, policy); err != nil {
		// If the policy failed validation, don't err. Fail the policy
		perr := PolicyError{}
		if errors.As(err, &perr) {
			return failPolicyWithError(policy, nil, subject, perr), nil
		}
		// ..else something broke
		return nil, fmt.Errorf("checking policy: %w", err)
	}

	// Build the required evaluators
	evaluators, err := ampel.impl.BuildEvaluators(opts, policy)
	if err != nil {
		return nil, fmt.Errorf("building evaluators: %w", err)
	}

	// Parse any extra attestation files defined in the options
	atts, err := ampel.impl.ParseAttestations(ctx, opts.AttestationFiles)
	if err != nil {
		return nil, fmt.Errorf("parsing single attestations: %w", err)
	}

	evalContext, err := ampel.impl.AssembleEvalContextValues(ctx, opts, policy.GetContext())
	if err != nil {
		return nil, fmt.Errorf("assembling policy context: %w", err)
	}

	// Process chained subjects. These have access to all the read attestations
	// even when some will be discarded in the next step. Computing the chain
	// will use the configured repositories if more attestations are required.
	var chain []*papi.ChainedSubject
	subject, chain, policyFail, err := ampel.impl.ProcessChainedSubjects(
		ctx, opts, evaluators, ampel.Collector, policy, evalContext, subject, atts,
	)
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
	// Option: Unsigned statements cause a:fail or b:ignore
	allow, ids, idErrors, err := ampel.impl.CheckIdentities(opts, policy.Identities, atts)
	if err != nil {
		return nil, fmt.Errorf("error validating signer identity: %w", err)
	}

	if !allow {
		return failPolicyWithError(policy, chain, subject, PolicyError{
			error:    errors.New("attestation identity validation failed"),
			Guidance: errors.Join(idErrors...).Error(),
		}), nil
	}

	// Filter attestations to those applicable to the subject
	preds, err := ampel.impl.FilterAttestations(opts, subject, atts, ids)
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

	// Evaluate the Policy
	result, err := ampel.impl.VerifySubject(ctx, opts, evaluators, policy, evalContext, subject, preds)
	if err != nil {
		return nil, fmt.Errorf("verifying subject: %w", err)
	}

	result.Chain = chain

	// Assert the status from the evaluation results
	if err := ampel.impl.AssertResult(policy, result); err != nil {
		return nil, fmt.Errorf("asserting results: %w", err)
	}

	// Generate outputs
	return result, nil
}

// AttestResult writes an attestation capturing an evaluation result
func (ampel *Ampel) AttestResult(w io.Writer, result *papi.Result) error {
	return ampel.impl.AttestResultToWriter(w, result)
}

// AttestResult writes an attestation capturing an evaluation result
func (ampel *Ampel) AttestResults(w io.Writer, results papi.Results) error {
	switch r := results.(type) {
	case *papi.Result:
		rs := &papi.ResultSet{
			Results:   []*papi.Result{r},
			DateStart: r.DateStart,
			DateEnd:   r.DateEnd,
		}
		if err := rs.Assert(); err != nil {
			return fmt.Errorf("asserting results set: %w", err)
		}
		return ampel.impl.AttestResultSetToWriter(w, rs)
	case *papi.ResultSet:
		return ampel.impl.AttestResultSetToWriter(w, r)
	default:
		return fmt.Errorf("results are not result or resultset")
	}
}

// failPolicySetWithError completes a policy set and sets the specified error
func failPolicySetWithError(set *papi.ResultSet, err error) *papi.ResultSet {
	guidance := ""
	//nolint:errorlint
	if pe, ok := err.(PolicyError); ok {
		guidance = pe.Guidance
	}

	set.Error = &papi.Error{
		Message:  err.Error(),
		Guidance: guidance,
	}

	set.DateEnd = timestamppb.Now()
	return set
}

// failPolicyWithError returns a failed status result for the policicy where all
// tennets are failed with error err. If err is a `PolicyError` then the result
// error guidance for the tenets will be read from it.
func failPolicyWithError(p *papi.Policy, chain []*papi.ChainedSubject, subject attestation.Subject, err error) *papi.Result {
	if subject == nil {
		subject = &gointoto.ResourceDescriptor{}
	}
	res := &papi.Result{
		Status:    papi.StatusFAIL,
		DateStart: timestamppb.Now(),
		DateEnd:   timestamppb.Now(),
		Policy: &papi.PolicyRef{
			Id:      p.Id,
			Version: p.GetMeta().GetVersion(),
		},
		EvalResults: []*papi.EvalResult{},
		Meta:        p.GetMeta(),
		Chain:       chain,
		Subject: &gointoto.ResourceDescriptor{
			Name:   subject.GetName(),
			Uri:    subject.GetUri(),
			Digest: subject.GetDigest(),
		},
	}

	guidance := ""
	//nolint:errorlint
	if pe, ok := err.(PolicyError); ok {
		guidance = pe.Guidance
	}
	for _, t := range p.Tenets {
		er := &papi.EvalResult{
			Id:         t.Id,
			Status:     papi.StatusFAIL,
			Date:       timestamppb.Now(),
			Output:     nil,
			Statements: nil, // Or do we define it?
			Error: &papi.Error{
				Message:  err.Error(),
				Guidance: guidance,
			},
			Assessment: nil,
		}
		res.EvalResults = append(res.EvalResults, er)
	}
	return res
}
