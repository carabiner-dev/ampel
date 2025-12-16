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
	sapi "github.com/carabiner-dev/signer/api/v1"
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
		rs, err := ampel.VerifySubjectWithPolicyGroup(ctx, opts, v, subject)
		if err != nil {
			return nil, fmt.Errorf("evaluating policy group: %w", err)
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

	// Load the policyset eval ctx definition into the go contect
	ctx, evalContext := ampel.loadElementEvalContextDef(ctx, policySet)

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

	evalContext.ChainedSubjects = chain

	// Rebuild the go context as we are now shipping the chained subjects.
	ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalContext)

	// If the chain returned no subjects, then we return an error unless
	// the verifier was explicitly set to allow empty chains.
	if len(policySet.GetChain()) > 0 && len(subjects) == 0 {
		if !opts.AllowEmptySetChains {
			return nil, fmt.Errorf("unable to complete evidence chain, no subject returned from selectors")
		}
		return softPassPolicySet(ctx, policySet, resultSet)
	}

	var mtx sync.Mutex
	t := throttler.New(int(opts.ParallelWorkers), len(policySet.Policies)*len(subjects))
	// Now cycle each policy....
	for i, pcy := range policySet.GetPolicies() {
		// ... and evaluate against each subject
		for _, subsubject := range subjects {
			go func(policy *papi.Policy, subject attestation.Subject, policyIndex int) {
				res, err := ampel.VerifySubjectWithPolicy(ctx, &opts, policy, subject)
				if err != nil {
					t.Done(fmt.Errorf("evaluating policy #%d: %w", policyIndex, err))
					return
				}
				mtx.Lock()
				resultSet.Results = append(resultSet.Results, res)
				mtx.Unlock()
				t.Done(nil)
			}(pcy, subsubject, i)
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

// VerifySubjectWithPolicyGroup evaluates a policy group and its blocks
func (ampel *Ampel) VerifySubjectWithPolicyGroup(
	ctx context.Context, oOpts *VerificationOptions, group *papi.PolicyGroup, subject attestation.Subject,
) (*papi.ResultGroup, error) {
	// DeepCopy the options as we will mutate them after parsing the initial
	// attestations set.
	opts := *oOpts

	// Now that we have a clone of the options, parse and add the
	// policySet's keys to the options set to reuse in the policies
	keys, err := group.PublicKeys()
	if err != nil {
		return nil, fmt.Errorf("reading PolicySet keys: %w", err)
	}
	opts.Keys = append(opts.Keys, keys...)

	// Resuktset to return
	res := &papi.ResultGroup{
		Status:    papi.StatusPASS,
		DateStart: timestamppb.Now(),
		DateEnd:   timestamppb.Now(),
		Group: &papi.PolicyGroupRef{
			Id:      group.GetId(),
			Version: group.GetMeta().GetVersion(),
			// Identity: &papi.Identity{},
			Location: group.GetSource().GetLocation(),
		},
		EvalResults: []*papi.BlockEvalResult{},
		Meta:        group.GetMeta(),
		Context:     &structpb.Struct{},
		Chain:       []*papi.ChainedSubject{},
		Common: &papi.ResultSetCommon{
			Context: &structpb.Struct{},
		},
	}

	// Check if the policy is viable before
	if err := ampel.impl.CheckPolicyGroup(ctx, &opts, group); err != nil {
		// If the policygroup failed validation, don't err. Fail the evaluation
		perr := PolicyError{}
		if errors.As(err, &perr) {
			return failPolicyGroupWithError(group, nil, subject, err), nil
		}
		// else something broke
		return nil, fmt.Errorf("checking policy: %w", err)
	}

	// Build the required evaluators
	evaluators, err := ampel.impl.BuildGroupEvaluators(&opts, group)
	if err != nil {
		return nil, fmt.Errorf("building evaluators: %w", err)
	}

	// Parse any extra attestation files defined in the options
	atts, err := ampel.impl.ParseAttestations(ctx, &opts, subject)
	if err != nil {
		return nil, fmt.Errorf("parsing single attestations: %w", err)
	}

	// Load the policyset eval ctx definition into the go contect
	ctx, evalContext := ampel.loadElementEvalContextDef(ctx, group)

	// Here we build the context that will be common for all policies as defined
	// in the policy group.
	evalContextValues, err := ampel.impl.AssembleEvalContextValues(ctx, &opts, group.GetCommon().GetContext())
	if err != nil {
		return nil, fmt.Errorf("assembling policy context: %w", err)
	}
	// Process chained subjects. These have access to all the read attestations
	// even when some will be discarded in the next step. Computing the chain
	// will use the configured repositories if more attestations are required.
	var chain []*papi.ChainedSubject

	subject, chain, policyFail, err := ampel.impl.ProcessChainedSubjects(
		ctx, &opts, evaluators, ampel.Collector, group, evalContextValues, subject, atts,
	)
	if err != nil {
		// If policyFail is true, then we don't return an error but rather
		// a policy fail result based on the error
		if policyFail {
			return failPolicyGroupWithError(group, chain, subject, err), nil
		}
		return nil, fmt.Errorf("processing chained subject: %w", err)
	}

	res.Subject = &gointoto.ResourceDescriptor{
		Name:   subject.GetName(),
		Uri:    subject.GetUri(),
		Digest: subject.GetDigest(),
	}

	evalContext.ChainedSubjects = chain

	// Rebuild the go context as we are now shipping the chained subjects.
	ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalContext)

	// Now  that we have the computed context, populate the resultset common context
	// with the computed values. The common context is guaranteed to have an entry
	// matching the definition un the policySet common, even if nil.
	commonContext := map[string]any{}
	for contextValName := range group.GetCommon().GetContext() {
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
		res.Common = &papi.ResultSetCommon{
			Context: spb,
		}
	}

	// Extract context values
	for i := range group.GetBlocks() {
		rs, err := ampel.verifySubjectWithBlock(ctx, &opts, group.GetBlocks()[i], subject)
		if err != nil {
			return nil, fmt.Errorf("verifying block: %w", err)
		}

		res.EvalResults = append(res.EvalResults, rs)
	}

	// Assert the group results. For the group to pass all blocks
	// need to pass.
	fails := []string{}
	for i := range res.EvalResults {
		if res.EvalResults[i].GetStatus() == papi.StatusFAIL {
			res.Status = papi.StatusFAIL
			if res.EvalResults[i].GetId() != "" {
				fails = append(fails, res.EvalResults[i].GetId())
			} else {
				fails = append(fails, fmt.Sprintf("group #%d", i))
			}
		}
	}
	if len(fails) > 0 && res.Status == papi.StatusFAIL {
		res.Error = fmt.Sprintf("Evaluation failed by blocks %v", fails)
	}

	// Record the end of the group eval
	res.DateEnd = timestamppb.Now()
	return res, nil
}

func (ampel *Ampel) verifySubjectWithBlock(
	ctx context.Context, opts *VerificationOptions, block *papi.PolicyBlock, subject attestation.Subject,
) (*papi.BlockEvalResult, error) {
	rset := &papi.BlockEvalResult{
		Status:  papi.StatusPASS,
		Meta:    block.GetMeta(),
		Id:      block.GetId(),
		Results: []*papi.Result{},
		Error:   &papi.Error{},
	}

	if block.GetMeta().GetAssertMode() == "OR" {
		rset.Status = papi.StatusFAIL
	}

	// Evaluate the block's policies
	// TODO(puerco): Parallelize this thing
	for i := range block.GetPolicies() {
		res, err := ampel.VerifySubjectWithPolicy(ctx, opts, block.GetPolicies()[i], subject)
		if err != nil {
			return nil, fmt.Errorf("verifying policy #%d: %w", i, err)
		}
		rset.Results = append(rset.Results, res)

		if res.GetStatus() == papi.StatusFAIL && block.GetMeta().GetAssertMode() == "" || block.GetMeta().GetAssertMode() == "AND" {
			rset.Status = papi.StatusFAIL
			if opts.LazyBlockEval {
				break
			}
		}

		if res.GetStatus() == papi.StatusPASS && block.GetMeta().GetAssertMode() == "OR" {
			rset.Status = papi.StatusPASS
			if opts.LazyBlockEval {
				break
			}
		}
	}
	return rset, nil
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
	case *papi.ResultGroup:
		rs := &papi.ResultSet{
			Groups:    []*papi.ResultGroup{r},
			DateStart: r.DateStart,
			DateEnd:   r.DateEnd,
		}
		if err := rs.Assert(); err != nil {
			return fmt.Errorf("asserting results set: %w", err)
		}
		return ampel.impl.AttestResultSetToWriter(w, rs)
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

// failPolicyGroupWithError returns a failed status result for the policyGroup
func failPolicyGroupWithError(p *papi.PolicyGroup, chain []*papi.ChainedSubject, subject attestation.Subject, err error) *papi.ResultGroup {
	if subject == nil {
		subject = &gointoto.ResourceDescriptor{}
	}
	res := &papi.ResultGroup{
		Status:    papi.StatusFAIL,
		DateStart: timestamppb.Now(),
		DateEnd:   timestamppb.Now(),
		Group: &papi.PolicyGroupRef{
			Id:      p.Id,
			Version: p.GetMeta().GetVersion(),
		},
		// TODO
		EvalResults: []*papi.BlockEvalResult{},
		Meta:        p.GetMeta(),
		Chain:       chain,
		Subject: &gointoto.ResourceDescriptor{
			Name:   subject.GetName(),
			Uri:    subject.GetUri(),
			Digest: subject.GetDigest(),
		},
		Error: err.Error(),
	}

	return res
}

// loadElementEvalContextDef adds the evaluation context definition from the element
// into the Go context (many context, I know :P)  If there is already an eval context
// in the go context, we add the new definitions from the policy material element.
//
// Returns the new go context loaded with the augmented eval ctx definition and the
// new evaluation context.
func (ampel *Ampel) loadElementEvalContextDef(ctx context.Context, element papi.CommonProvider) (context.Context, evalcontext.EvaluationContext) {
	// First, extract any existing evaluation context
	evalContext, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if !ok {
		evalContext = evalcontext.EvaluationContext{
			Context:    map[string]*papi.ContextVal{},
			Identities: []*sapi.Identity{},
		}
	}

	// If the policy material has an eval context definition, then parse it and add
	// it to the the Go context payload
	if element.GetCommon() != nil && element.GetCommon().GetContext() != nil {
		for key, val := range element.GetCommon().GetContext() {
			evalContext.Context[key] = val
		}
	}

	// Pass the policySet identities to the individual policy evaluations
	if element.GetCommon() != nil && element.GetCommon().GetIdentities() != nil {
		// TODO(puerco): Here we should check if the context already has the same
		// identity to avoid duplication
		evalContext.Identities = append(evalContext.Identities, element.GetCommon().GetIdentities()...)
	}

	return context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalContext), evalContext
}

func softPassPolicySet(ctx context.Context, policySet *papi.PolicySet, resultSet *papi.ResultSet) (*papi.ResultSet, error) {
	evalContext, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if !ok {
		evalContext = evalcontext.EvaluationContext{}
	}

	structVals, err := structpb.NewStruct(evalContext.ContextValues)
	if err != nil {
		return nil, fmt.Errorf("structuring context data: %w", err)
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
						Message:  "Policy not evaluated, chain is empty",
						Guidance: "The policySet selectors did not return any subjects to verify",
					},
				},
			},
			Meta:    pcy.GetMeta(),
			Context: structVals,
			Chain:   evalContext.ChainedSubjects,
		})
	}

	return resultSet, nil
}
