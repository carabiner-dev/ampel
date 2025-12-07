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
	"sync"

	"github.com/carabiner-dev/attestation"
	papi "github.com/carabiner-dev/policy/api/v1"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/nozzle/throttler"
	"google.golang.org/protobuf/types/known/structpb"
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
	case *papi.PolicyGroup:
		return nil, fmt.Errorf("PolicyGroups are not yet supported")
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
	ctx context.Context, originalOptions *VerificationOptions, policySet *papi.PolicySet, subject attestation.Subject,
) (*papi.ResultSet, error) {
	// Copy the options as we will mutate them after parsing the initial
	// attestations set.
	opts := *originalOptions

	// Now that we have a clone of the options, parse and add the
	// policySet's keys to the options set to reuse in the policies
	keys, err := policySet.PublicKeys()
	if err != nil {
		return nil, fmt.Errorf("reading PolicySet keys: %w", err)
	}
	opts.Keys = append(opts.Keys, keys...)

	// This is the resultSet to be returned
	resultSet := &papi.ResultSet{
		PolicySet: &papi.PolicyRef{
			Id:      policySet.GetId(),
			Version: policySet.GetMeta().GetVersion(),
			// Identity: &papi.Identity{},
			// Location: &gointoto.ResourceDescriptor{},
		},
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
	if err := ampel.impl.CheckPolicySet(ctx, &opts, policySet); err != nil {
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
		policyEvals, err := ampel.impl.BuildEvaluators(&opts, p)
		if err != nil {
			return nil, fmt.Errorf("building evaluators: %w", err)
		}
		maps.Insert(evaluators, maps.All(policyEvals))
	}

	// Parse any extra attestation files defined in the options
	atts, err := ampel.impl.ParseAttestations(ctx, &opts, subject)
	if err != nil {
		return nil, fmt.Errorf("parsing single attestations: %w", err)
	}

	// Mutate the options set to avoid reparsing the paths
	opts.AttestationFiles = []string{}
	opts.Attestations = atts

	// Add the (eval) context, to the (go) context :P
	evalContext, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if !ok {
		evalContext = evalcontext.EvaluationContext{}
	}

	// If the policy set has an eval context definition, then parse it and add
	// it to the the Go context payload
	if policySet.GetCommon() != nil && policySet.GetCommon().GetContext() != nil {
		evalContext.Context = policySet.GetCommon().GetContext()
	}

	// Pass the policySet identities to the individual policy evaluations
	evalContext.Identities = policySet.GetCommon().GetIdentities()

	// Build the context to pass to the policy evaluations
	ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalContext)

	// Here we build the context that will be common for all policies as defined
	// in the policy set.
	evalContextValues, err := ampel.impl.AssembleEvalContextValues(ctx, &opts, policySet.GetCommon().GetContext())
	if err != nil {
		return nil, fmt.Errorf("assembling policy context: %w", err)
	}

	// Now  that we have the computed context, populate the resultset common context
	// with the computed values. The common context is guaranteed to have an entry
	// matching the definition un the policySet common, even if nil.
	commonContext := map[string]any{}
	for contextValName := range policySet.GetCommon().GetContext() {
		if v, ok := evalContextValues[contextValName]; ok {
			commonContext[contextValName] = v
		} else {
			commonContext[contextValName] = nil
		}
	}

	if len(commonContext) > 0 {
		spb, err := structpb.NewStruct(commonContext)
		if err != nil {
			return nil, fmt.Errorf("building computed common context proto: %w", err)
		}
		resultSet.Common = &papi.ResultSetCommon{
			Context: spb,
		}
	}

	structVals, err := structpb.NewStruct(evalContext.ContextValues)
	if err != nil {
		return nil, fmt.Errorf("structuring context data: %w", err)
	}

	// Process policySet chain
	subjects, chain, policyFail, err := ampel.impl.ProcessPolicySetChainedSubjects(
		ctx, &opts, evaluators, ampel.Collector, policySet, evalContextValues, subject, atts,
	)
	if err != nil {
		// If policyFail is true, then we don't return an error but rather
		// a policy fail result based on the error
		if policyFail {
			return failPolicySetWithError(resultSet, err), nil
		}
		return nil, fmt.Errorf("processing chained subject: %w", err)
	}

	// If the chain returned not subjects, then we return an error unless
	// the verifier was explicitly set to allow empty chains.
	if len(policySet.GetChain()) > 0 && len(subjects) == 0 {
		if !opts.AllowEmptySetChains {
			return nil, fmt.Errorf("unable to complete evidence chain, no subject returned from selectors")
		}
		resultSet.Error = &papi.Error{
			Message:  "unable to complete evidence chain",
			Guidance: "PolicySet selectors did not return any subjects when evaluated",
		}
		resultSet.Status = papi.StatusPASS
		resultSet.DateEnd = timestamppb.Now()
		for _, pcy := range policySet.Policies {
			resultSet.Results = append(resultSet.Results, &papi.Result{
				Status:    papi.StatusSOFTFAIL,
				DateStart: resultSet.GetDateStart(),
				DateEnd:   timestamppb.Now(),
				Policy: &papi.PolicyRef{
					Id:       pcy.GetId(),
					Version:  pcy.GetMeta().GetVersion(),
					Location: pcy.GetSource().GetLocation(),
				},
				EvalResults: []*papi.EvalResult{
					{
						Status: papi.StatusSOFTFAIL,
						Date:   timestamppb.Now(),
						Error: &papi.Error{
							Message:  "Policy not evaluated, empty chain",
							Guidance: "The policySet selectors did not return subject to verify",
						},
					},
				},
				Meta:    pcy.GetMeta(),
				Context: structVals,
				Chain:   chain,
			})
		}

		return resultSet, nil
	}

	evalContext.ChainedSubjects = chain

	// Rebuild the go context as we are now shipping the chained subjects.
	ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalContext)

	var mtx sync.Mutex
	t := throttler.New(int(opts.ParallelWorkers), len(policySet.Policies)*len(subjects))
	// Now cycle each policy....
	for i, pcy := range policySet.GetPolicies() {
		// ... and evaluate against each subject
		for _, subsubject := range subjects {
			go func() {
				res, err := ampel.VerifySubjectWithPolicy(ctx, &opts, pcy, subsubject)
				if err != nil {
					t.Done(fmt.Errorf("evaluating policy #%d: %w", i, err))
					return
				}
				mtx.Lock()
				resultSet.Results = append(resultSet.Results, res)
				mtx.Unlock()
				t.Done(nil)
			}()
			// Break and return on the first error
			if numErrs := t.Throttle(); numErrs != 0 {
				return nil, t.Err()
			}
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
	atts, err := ampel.impl.ParseAttestations(ctx, opts, subject)
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

	// Check identities to see if the attestations can be admitted
	// TODO(puerco)
	// Option: Unsigned statements cause a:fail or b:ignore
	allow, ids, idErrors, err := ampel.impl.CheckIdentities(ctx, opts, policy.GetIdentities(), atts)
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

// subjectToString builds a string to make a subject more human-readable
func subjectToString(subject attestation.Subject) string {
	vals := []string{}
	for algo, val := range subject.GetDigest() {
		if len(val) < 7 {
			continue
		}
		vals = append(vals, fmt.Sprintf("%s:%s", algo, val[0:6]))
	}
	var str string

	if subject.GetName() != "" {
		str = subject.GetName() + " "
	} else if subject.GetUri() != "" {
		str = subject.GetUri() + " "
	}

	if len(vals) > 0 {
		str += fmt.Sprintf("%+v", vals)
	}
	return str
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
