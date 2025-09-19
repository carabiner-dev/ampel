// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector"
	"github.com/carabiner-dev/collector/envelope"
	"github.com/carabiner-dev/collector/filters"
	ampelPred "github.com/carabiner-dev/collector/predicate/ampel"
	"github.com/carabiner-dev/collector/statement/intoto"
	papi "github.com/carabiner-dev/policy/api/v1"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	acontext "github.com/carabiner-dev/ampel/pkg/context"
	"github.com/carabiner-dev/ampel/pkg/evaluator"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/evalcontext"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
	"github.com/carabiner-dev/ampel/pkg/transformer"
)

// AmpelImplementation
type AmpelVerifier interface {
	// CheckPolicy verifies the policy is sound to evaluate before running it
	CheckPolicy(context.Context, *VerificationOptions, *papi.Policy) error
	CheckPolicySet(context.Context, *VerificationOptions, *papi.PolicySet) error
	GatherAttestations(context.Context, *VerificationOptions, *collector.Agent, *papi.Policy, attestation.Subject, []attestation.Envelope) ([]attestation.Envelope, error)
	ParseAttestations(context.Context, []string) ([]attestation.Envelope, error)
	BuildEvaluators(*VerificationOptions, *papi.Policy) (map[class.Class]evaluator.Evaluator, error)
	BuildTransformers(*VerificationOptions, *papi.Policy) (map[transformer.Class]transformer.Transformer, error)
	Transform(*VerificationOptions, map[transformer.Class]transformer.Transformer, *papi.Policy, attestation.Subject, []attestation.Predicate) (attestation.Subject, []attestation.Predicate, error)

	// CheckIdentities verifies that attestations are signed by the policy identities
	CheckIdentities(*VerificationOptions, []*papi.Identity, []attestation.Envelope) (bool, [][]*papi.Identity, []error, error)

	FilterAttestations(*VerificationOptions, attestation.Subject, []attestation.Envelope, [][]*papi.Identity) ([]attestation.Predicate, error)
	AssertResult(*papi.Policy, *papi.Result) error
	AttestResults(context.Context, *VerificationOptions, papi.Results) error

	// AttestResultToWriter takes an evaluation result and writes an attestation to the supplied io.Writer
	AttestResultToWriter(io.Writer, *papi.Result) error

	// AttestResultSetToWriter takes an policy resultset and writes an attestation to the supplied io.Writer
	AttestResultSetToWriter(io.Writer, *papi.ResultSet) error

	// VerifySubject runs the verification process.
	VerifySubject(context.Context, *VerificationOptions, map[class.Class]evaluator.Evaluator, *papi.Policy, map[string]any, attestation.Subject, []attestation.Predicate) (*papi.Result, error)

	// ProcessChainedSubjects proceses the chain of attestations to find the ultimate
	// subject a policy is supposed to operate on
	ProcessChainedSubjects(context.Context, *VerificationOptions, map[class.Class]evaluator.Evaluator, *collector.Agent, *papi.Policy, map[string]any, attestation.Subject, []attestation.Envelope) (attestation.Subject, []*papi.ChainedSubject, bool, error)

	// ProcessPolicySetChainedSubjects executesd a PolicySet's ChainLink and returns
	// the resulting list of subjects from the evaluator.
	ProcessPolicySetChainedSubjects(context.Context, *VerificationOptions, map[class.Class]evaluator.Evaluator, *collector.Agent, *papi.PolicySet, map[string]any, attestation.Subject, []attestation.Envelope) ([]attestation.Subject, []*papi.ChainedSubject, bool, error)

	// AssembleEvalContextValues builds the policy context values by mixing defaults and defined values
	AssembleEvalContextValues(context.Context, *VerificationOptions, map[string]*papi.ContextVal) (map[string]any, error)
}

type defaultIplementation struct{}

// CheckPolicy verifies the policy before evaluation to ensure it is fit to run.
func (di *defaultIplementation) CheckPolicy(ctx context.Context, opts *VerificationOptions, p *papi.Policy) error {
	if opts == nil {
		return errors.New("verifier options are not set")
	}
	if p.GetMeta() != nil &&
		p.GetMeta().GetExpiration() != nil &&
		p.GetMeta().GetExpiration().AsTime().Before(time.Now()) &&
		opts.EnforceExpiration {
		return PolicyError{
			error: errors.New("the policy has expired"), // TODO(puerco): Const error
			Guidance: fmt.Sprintf(
				"The policy expired on %s, update the policy source",
				p.GetMeta().GetExpiration().AsTime().Format(time.UnixDate),
			),
		}
	}
	return nil
}

// CheckPolicySet verifies the policySet before evaluating its policies to ensure
// it is fit to run.
func (di *defaultIplementation) CheckPolicySet(ctx context.Context, opts *VerificationOptions, set *papi.PolicySet) error {
	if opts == nil {
		return errors.New("verifier options are not set")
	}
	if set.GetMeta() != nil &&
		set.GetMeta().GetExpiration() != nil &&
		set.GetMeta().GetExpiration().AsTime().Before(time.Now()) &&
		opts.EnforceExpiration {
		return PolicyError{
			error: errors.New("the policy has expired"), // TODO(puerco): Const error
			Guidance: fmt.Sprintf(
				"The policySet expired on %s, update the policy source",
				set.GetMeta().GetExpiration().AsTime().Format(time.UnixDate),
			),
		}
	}
	return nil
}

// GatherAttestations assembles the attestations pack required to run the
// evaluation. It first filters the attestations loaded manually by matching
// their descriptors against the chained subject and keeping those without
// a subject.
func (di *defaultIplementation) GatherAttestations(
	ctx context.Context, opts *VerificationOptions, agent *collector.Agent,
	policy *papi.Policy, subject attestation.Subject, attestations []attestation.Envelope,
) ([]attestation.Envelope, error) {
	// First, any predefined attestations (from the command line) need to be
	// filtered out as no subject matching is done. This is because we ingest
	// all of them in case they are needed when computing the chained subjects.

	digest := subject.GetDigest()

	// Here we apply the gitCommit hack if it's tuned on
	if opts.GitCommitShaHack {
		_, hasCommit := digest[string(gointoto.AlgorithmGitCommit)]
		_, hasSHA1 := digest[string(gointoto.AlgorithmSHA1)]

		if hasCommit && !hasSHA1 && len(digest[string(gointoto.AlgorithmGitCommit)]) == 40 {
			digest[string(gointoto.AlgorithmSHA1)] = digest[string(gointoto.AlgorithmGitCommit)]
		} else if hasSHA1 && !hasCommit {
			digest[string(gointoto.AlgorithmGitCommit)] = digest[string(gointoto.AlgorithmSHA1)]
		}

		// Clone the subject with te updated digests
		subject = &gointoto.ResourceDescriptor{
			Name:   subject.GetName(),
			Uri:    subject.GetUri(),
			Digest: digest,
		}
	}

	// ... but we also need to keep the specified attestations that don't
	// have a subject. These come from bare json files, such as unsigned SBOMs
	attestations = attestation.NewQuery().WithFilter(
		&filters.SubjectHashMatcher{
			HashSets: []map[string]string{digest},
		},
		&filters.SubjectlessMatcher{},
	).Run(attestations, attestation.WithMode(attestation.QueryModeOr))

	// Now, query the collector to get all attestations available for the artifact.
	res, err := agent.FetchAttestationsBySubject(ctx, []attestation.Subject{subject})
	if err != nil {
		if !errors.Is(err, collector.ErrNoFetcherConfigured) {
			return nil, fmt.Errorf("collecting attestations: %w", err)
		} else {
			logrus.Warn(err)
			return []attestation.Envelope{}, nil
		}
	}
	return append(attestations, res...), nil
}

// ParseAttestations parses additional attestations defined to support the
// subject verification
func (di *defaultIplementation) ParseAttestations(ctx context.Context, paths []string) ([]attestation.Envelope, error) {
	errs := []error{}
	res := []attestation.Envelope{}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		logrus.Debugf("parsing %s (%d envelope drivers loaded)", path, len(envelope.Parsers))
		env, err := envelope.Parsers.Parse(f)
		if err != nil {
			errs = append(errs, fmt.Errorf("parsing %q: %w", path, err))
			continue
		}

		if env == nil {
			return nil, fmt.Errorf("unable to obtain envelope from: %q", path)
		}
		res = append(res, env...)
	}
	return res, errors.Join(errs...)
}

// AssertResult conducts the final assertion to allow/block based on the
// result sets returned by the evaluators.
func (di *defaultIplementation) AssertResult(policy *papi.Policy, result *papi.Result) error {
	switch policy.GetMeta().GetAssertMode() {
	case "OR", "":
		for _, er := range result.EvalResults {
			if er.Status == papi.StatusPASS {
				result.Status = papi.StatusPASS
				return nil
			}
		}
		result.Status = papi.StatusFAIL
		if policy.Meta.Enforce == "OFF" {
			result.Status = papi.StatusSOFTFAIL
		}
	case "AND":
		for _, er := range result.EvalResults {
			if er.Status == papi.StatusFAIL {
				result.Status = papi.StatusFAIL
				if policy.Meta.Enforce == "OFF" {
					result.Status = papi.StatusSOFTFAIL
				}
				return nil
			}
		}
		result.Status = papi.StatusPASS
	default:
		return fmt.Errorf("invalid policy assertion mode")
	}
	return nil
}

// BuildEvaluators checks a policy and build the required evaluators to run the tenets
func (di *defaultIplementation) BuildEvaluators(opts *VerificationOptions, p *papi.Policy) (map[class.Class]evaluator.Evaluator, error) {
	evaluators := map[class.Class]evaluator.Evaluator{}
	factory := evaluator.Factory{}
	// First, build the default evaluator
	def := class.Class(p.GetMeta().GetRuntime())

	// Compute the default runtime, first from the options received.
	// If not set, then from the default options set.
	if p.GetMeta().GetRuntime() == "" {
		if opts.DefaultEvaluator != "" {
			def = opts.DefaultEvaluator
		} else {
			def = DefaultVerificationOptions.DefaultEvaluator
		}
	}

	e, err := factory.Get(&opts.EvaluatorOptions, def)
	if err != nil {
		return nil, fmt.Errorf("unable to build default runtime: %w", err)
	}
	logrus.Debugf("Registered default evaluator of class %s", def)
	evaluators[class.Class("default")] = e
	evaluators[def] = e
	if p.GetMeta().GetRuntime() != "" {
		evaluators[class.Class(p.GetMeta().GetRuntime())] = e
	}

	for _, link := range p.GetChain() {
		if classString := link.GetPredicate().GetRuntime(); classString != "" {
			e, err := factory.Get(&opts.EvaluatorOptions, def)
			if err != nil {
				return nil, fmt.Errorf("unable to build chained subject runtime")
			}
			logrus.Debugf("registered evaluator of class %s for chained predicate", classString)
			evaluators[class.Class(classString)] = e
		}
	}

	for _, t := range p.Tenets {
		if t.Runtime == "" {
			continue
		}
		cl := class.Class(t.Runtime)
		if _, ok := evaluators[cl]; ok {
			continue
		}
		// TODO(puerco): Options here should come from the verifier options
		e, err := factory.Get(&options.EvaluatorOptions{}, cl)
		if err != nil {
			return nil, fmt.Errorf("building %q runtime: %w", t.Runtime, err)
		}
		evaluators[cl] = e
		logrus.Debugf("Registered evaluator of class %s", cl)
	}

	if len(evaluators) == 0 {
		return nil, errors.New("no valid runtimes found for policy tenets")
	}
	return evaluators, nil
}

// BuildTransformers
func (di *defaultIplementation) BuildTransformers(opts *VerificationOptions, policy *papi.Policy) (map[transformer.Class]transformer.Transformer, error) {
	factory := transformer.Factory{}
	transformers := map[transformer.Class]transformer.Transformer{}
	for _, classString := range policy.Transformers {
		t, err := factory.Get(transformer.Class(classString.Id))
		if err != nil {
			return nil, fmt.Errorf("building tranformer for class %q: %w", classString, err)
		}
		transformers[transformer.Class(classString.Id)] = t
	}
	logrus.Debugf("Loaded %d transformers defined in the policy", len(transformers))
	return transformers, nil
}

// Transform takes the predicates and a set of transformers and applies the transformations
// defined in the policy
func (di *defaultIplementation) Transform(
	opts *VerificationOptions, transformers map[transformer.Class]transformer.Transformer,
	policy *papi.Policy, subject attestation.Subject, predicates []attestation.Predicate,
) (attestation.Subject, []attestation.Predicate, error) {
	var err error
	var newsubject attestation.Subject
	i := 0
	for _, t := range transformers {
		newsubject, predicates, err = t.Mutate(subject, predicates)
		if newsubject != nil {
			subject = newsubject
		}
		if err != nil {
			return nil, nil, fmt.Errorf("applying transformation #%d (%T): %w", i, t, err)
		}
		i++
	}
	ts := []string{}
	for _, s := range predicates {
		ts = append(ts, string(s.GetType()))
	}
	logrus.Debugf("Predicate types after transform: %v", ts)
	return subject, predicates, nil
}

// CheckIdentities checks that the ingested attestations are signed by one of the
// identities defined in the policy.
func (di *defaultIplementation) CheckIdentities(opts *VerificationOptions, policyIdentities []*papi.Identity, envelopes []attestation.Envelope) (bool, [][]*papi.Identity, []error, error) {
	// verification errors for the user
	errs := make([]error, len(envelopes))
	validSigners := make([][]*papi.Identity, len(envelopes))

	// allIds are the allowed ids (from the policy + any from options)
	allIds := []*papi.Identity{}
	allIds = append(allIds, policyIdentities...)

	if len(policyIdentities) > 0 && len(opts.IdentityStrings) > 0 {
		logrus.Warnf(
			"Policy has signer identities defined, %d identities from options will be ignored",
			len(opts.IdentityStrings))
	}

	// Add any identities defined in options
	if len(opts.IdentityStrings) > 0 && len(policyIdentities) == 0 {
		logrus.Debugf("Got %d identity strings from options", len(opts.IdentityStrings))
		for _, idSlug := range opts.IdentityStrings {
			ident, err := papi.NewIdentityFromSlug(idSlug)
			if err != nil {
				return false, nil, nil, fmt.Errorf("invalid identity slug %q: %w", idSlug, err)
			}
			allIds = append(allIds, ident)
		}
	}

	// If there are no identities defined, return here
	if len(allIds) == 0 {
		logrus.Debug("No identities defined in policy. Not checking.")
		return true, validSigners, nil, nil
	} else {
		logrus.Debug("Will look for signed attestations from:")
		for _, i := range allIds {
			logrus.Debugf("  > %s", i.Slug())
		}
	}

	validIdentities := true

	// First, verify the signatures on the envelopes
	for i, e := range envelopes {
		// Attestations are expected to be verified here already, but we want
		// to make sure. This should not be an issue as the verification data
		// should be already cached.

		if err := e.Verify(opts.Keys); err != nil {
			errs[i] = fmt.Errorf("verifying attestation signature: %w", err)
			validIdentities = false
			continue
		}

		if e.GetVerification() == nil || !e.GetVerification().GetVerified() {
			errs[i] = errors.New("attestation not verified")
			validIdentities = false
			continue
		}

		for _, id := range allIds {
			if e.GetVerification().MatchesIdentity(id) {
				validSigners[i] = append(validSigners[i], id)
			}
		}

		if len(validSigners) == 0 {
			validIdentities = false
			errs[i] = fmt.Errorf("attestation %d (type %s) has no recognized signer identities", i, e.GetStatement().GetType())
		}
	}

	// We don't use the errors yet, but at some point we should embed them into
	// the attestation verification.
	return validIdentities, validSigners, errs, nil
}

// FilterAttestations filters the attestations read to only those required by the
// policy. This function also restamps the ingested predicates with the identities
// verified against the policy when ingesting the attestations.
//
// TODO(puerco): Implement filtering before 1.0
func (di *defaultIplementation) FilterAttestations(opts *VerificationOptions, subject attestation.Subject, envs []attestation.Envelope, ids [][]*papi.Identity) ([]attestation.Predicate, error) {
	preds := []attestation.Predicate{}
	for i, env := range envs {
		pred := env.GetStatement().GetPredicate()
		pred.SetVerification(&papi.Verification{
			Signature: &papi.SignatureVerification{
				Date:       timestamppb.Now(),
				Verified:   true,
				Identities: ids[i],
			},
		})
		preds = append(preds, pred)
	}
	return preds, nil
}

// evaluateChain evaluates an evidence chain and returns the resulting subject
func (di *defaultIplementation) evaluateChain(
	ctx context.Context, opts *VerificationOptions, evaluators map[class.Class]evaluator.Evaluator,
	agent *collector.Agent, chainLinks []*papi.ChainLink, evalContextValues map[string]any, subject attestation.Subject,
	attestations []attestation.Envelope, globalIdentities []*papi.Identity, defaultEvalClass string,
) ([]attestation.Subject, []*papi.ChainedSubject, bool, error) {
	chain := []*papi.ChainedSubject{}
	logrus.Debug("Processing evidence chain")
	var subjectsList []attestation.Subject

	// Cycle all links and eval
	for i, link := range chainLinks {
		logrus.Debugf(" Link needs %s", link.GetPredicate().GetType())
		// Build an attestation query for the type we need
		q := attestation.NewQuery().WithFilter(
			&filters.PredicateTypeMatcher{
				PredicateTypes: map[attestation.PredicateType]struct{}{
					attestation.PredicateType(link.GetPredicate().GetType()): {},
				},
			},
		)

		if len(attestations) > 0 {
			attestations = q.Run(attestations)
		}

		// Only fetch more attestations from the configured sources if we need more:
		if len(attestations) == 0 {
			moreatts, err := agent.FetchAttestationsBySubject(
				ctx, []attestation.Subject{subject}, collector.WithQuery(q),
			)
			if err != nil {
				return nil, nil, false, fmt.Errorf("collecting attestations: %w", err)
			}
			attestations = append(attestations, moreatts...)
		}

		if len(attestations) == 0 {
			return nil, nil, true, PolicyError{
				error:    fmt.Errorf("no matching attestations to read the chained subject #%d", i),
				Guidance: "make sure the collector has access to attestations to satisfy the subject chain as defined in the policy.",
			}
		}

		// Here, we warn if we get more than one attestation for the chained
		// predicate. Probably this should be limited to only one.
		if len(attestations) > 1 {
			logrus.Warn("Chained subject builder got more than one statement")
		}

		if err := attestations[0].Verify(opts.Keys); err != nil {
			return nil, nil, true, PolicyError{
				error:    fmt.Errorf("signature verifying failed in chained subject: %w", err),
				Guidance: "the signature verification in the loaded attestations failed, try resigning it",
			}
		}
		var pass bool
		var err error
		var ids [][]*papi.Identity

		// Check the attestation identities for now, we fallback to the identities
		// defined in the policy if the link does not have its own. Probably this
		// should have a better default.
		if link.GetPredicate().GetIdentities() != nil {
			pass, ids, _, err = di.CheckIdentities(opts, link.GetPredicate().GetIdentities(), attestations[0:0])
		} else {
			pass, ids, _, err = di.CheckIdentities(opts, globalIdentities, attestations[0:0])
		}
		if err != nil {
			return nil, nil, false, fmt.Errorf("error checking attestation identity: %w", err)
		}
		if !pass {
			return nil, nil, true, PolicyError{
				error:    fmt.Errorf("unable to validate chained attestation identity"),
				Guidance: "the chained attestaion identity does not match the policy",
			}
		}

		// TODO: Mueve a metodos en policy.go
		classString := link.GetPredicate().GetRuntime()
		if classString == "" {
			classString = defaultEvalClass
		}
		if classString == "" {
			classString = string(opts.DefaultEvaluator)
		}

		// TODO(puerco): Options here should come from the verifier options
		key := class.Class(classString)
		if key == "" {
			key = class.Class("default")
		}
		if _, ok := evaluators[key]; !ok {
			return nil, nil, false, fmt.Errorf("no evaluator loaded for class %s", key)
		}

		// Populate the context data
		ectx, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
		if !ok {
			ectx = evalcontext.EvaluationContext{}
		}
		ectx.Subject = subject
		ectx.ContextValues = evalContextValues
		ctx := context.WithValue(ctx, evalcontext.EvaluationContextKey{}, ectx)

		// Execute the selector
		subjectsList, err = evaluators[key].ExecChainedSelector(
			ctx, &opts.EvaluatorOptions, link.GetPredicate(),
			attestations[0].GetStatement().GetPredicate(),
		)
		if err != nil {
			// TODO(puerco): The false here instructs ampel to return an error
			// (not a policy fail) when there is a syntax error in the policy
			// code (CEL or otherwise). Perhaps this should be configurable.
			return nil, nil, false, fmt.Errorf("evaluating chained subject code: %w", err)
		}

		if len(subjectsList) == 0 {
			return nil, nil, false, fmt.Errorf("failed to obtain a subject to fullfil predicate chain")
		}

		// All intermediate links MUST return only one subject because they point
		// to a new subject. Only the last link can return many subjects as
		// a PolicySet can fan out to point to many,
		if i+1 != len(chainLinks) && len(subjectsList) != 1 {
			return nil, nil, false, fmt.Errorf("chained selector must return exactly one subject (got %d)", len(subjectsList))
		}

		// Add to link history
		var goodIds []*papi.Identity
		if len(ids) > 0 {
			goodIds = ids[0]
		}
		chain = append(chain, &papi.ChainedSubject{
			Source:      newResourceDescriptorFromSubject(subject),
			Destination: newResourceDescriptorFromSubject(subjectsList[0]),
			Link: &papi.ChainedSubjectLink{
				Type:        string(attestations[0].GetStatement().GetPredicateType()),
				Attestation: newResourceDescriptorFromSubject(attestations[0].GetStatement().GetPredicate().GetOrigin()),
				Identities:  goodIds,
			},
		})
		subject = subjectsList[0]
	}
	return subjectsList, chain, false, nil
}

// SelectChainedSubject returns a new subkect from an ingested attestatom
func (di *defaultIplementation) ProcessChainedSubjects(
	ctx context.Context, opts *VerificationOptions, evaluators map[class.Class]evaluator.Evaluator,
	agent *collector.Agent, policy *papi.Policy, evalContextValues map[string]any, subject attestation.Subject,
	attestations []attestation.Envelope,
) (attestation.Subject, []*papi.ChainedSubject, bool, error) {
	chain := []*papi.ChainedSubject{}

	// If there are no chained subjects, return the original
	if policy.GetChain() == nil {
		return subject, chain, false, nil
	}

	// Get the default evaluator from the policy
	defaultEvalClass := ""
	if policy.GetMeta() != nil {
		defaultEvalClass = policy.GetMeta().GetRuntime()
	}

	// Here, we only pass the policy, the context will be completed on each eval
	ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalcontext.EvaluationContext{
		Policy: policy,
	})
	subjects, chain, fail, err := di.evaluateChain(
		ctx, opts, evaluators, agent, policy.GetChain(), evalContextValues, subject,
		attestations, policy.GetIdentities(), defaultEvalClass,
	)
	if err != nil {
		return nil, nil, false, err
	}

	if len(subjects) > 1 {
		return nil, nil, false, fmt.Errorf("processing chained subjects returned more than one subject")
	}

	if len(subjects) == 0 {
		return nil, nil, false, fmt.Errorf("unable to complete evidence chain, no subject returned")
	}

	return subjects[0], chain, fail, nil
}

func newResourceDescriptorFromSubject(s attestation.Subject) *gointoto.ResourceDescriptor {
	return &gointoto.ResourceDescriptor{
		Name:   s.GetName(),
		Uri:    s.GetUri(),
		Digest: s.GetDigest(),
	}
}

// AssembleEvalContextValues puts together the context values by assembling the context
// considering its defaults, received values from upstream and value providers.
func (di *defaultIplementation) AssembleEvalContextValues(ctx context.Context, opts *VerificationOptions, contextValues map[string]*papi.ContextVal) (map[string]any, error) {
	errs := []error{}

	// Load the context definitions as received from invocation
	values := map[string]any{}
	assembledContext := map[string]*papi.ContextVal{}

	// Context names can be any case, but they cannot clash when normalized
	// to lower case. This means that both MyValue and myvalue are valid names
	// but you cannot have both at the same time.
	lcnames := map[string]string{}
	fromParent := map[string]struct{}{} // This is to track if the value vas defined at the parent

	// Things using AMPEL send the definitions in the context
	preContext, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if ok {
		if preContext.ContextValues != nil {
			logrus.Warnf("Eval context has preloaded values. They will be discarded")
		}

		// Assemble the context structure from the struct received from ancestors
		// (eg if its coming from a PolicySet commons)
		if preContext.Context != nil {
			for k, v := range preContext.Context {
				// Validate key?
				assembledContext[k] = v
				if existingName, ok := lcnames[strings.ToLower(k)]; ok {
					if existingName != k {
						return nil, fmt.Errorf("parent context value name %q clashes with existing name %q", k, lcnames[strings.ToLower(k)])
					}
				}
				lcnames[strings.ToLower(k)] = k
				fromParent[k] = struct{}{}
			}
		}
	}

	// Override the ancestor context structure with the policy context
	// definition (if any)
	for k, def := range contextValues {
		// Check if there is an existing value name that clashed with this one
		// when normalized to lowercase
		if existingName, ok := lcnames[strings.ToLower(k)]; ok {
			if existingName != k {
				// Here choose which error to return
				if _, ok := fromParent[k]; ok {
					return nil, fmt.Errorf("context value name %q clashes with %q coming from parent context", k, lcnames[strings.ToLower(k)])
				}
				return nil, fmt.Errorf("context value name %q clashes with existing name %q", k, lcnames[strings.ToLower(k)])
			}
		}
		lcnames[strings.ToLower(k)] = k
		// Validate the key? Probably in a policy validation func
		if _, ok := assembledContext[k]; ok {
			assembledContext[k].Merge(def)
		} else {
			assembledContext[k] = def
		}
	}

	// Get the values from the configured providers
	definitions, err := acontext.GetValues(opts.ContextProviders, slices.Collect(maps.Keys(assembledContext)))
	if err != nil {
		return nil, fmt.Errorf("getting values from providers: %w", err)
	}

	logrus.Debugf("[CTX] Assembled Context: %+v", assembledContext)
	logrus.Debugf("[CTX] Context Values: %+v", definitions)

	// Assemble the context by overriding values in order
	for k, contextDef := range assembledContext {
		var v any
		// First case: If the policy has a burned in value, that is it.
		// Burned context values into the policy are signed and cannot
		// be modified.
		if contextDef.Value != nil {
			// Potential change:
			// Here if the defined values attempt to flip a value
			// burned in the policy code, perhaps we should return
			// an error instead of ignoring.
			values[k] = contextDef.Value.AsInterface()
			continue
		}

		// Second. The overridable base value is the policy default:
		if contextDef.Default != nil {
			v = contextDef.Default.AsInterface()
		}

		// Third. If there is a value defined, we override the default:
		if _, ok := definitions[k]; ok {
			v = definitions[k]
		}

		values[k] = v

		// Fail if the value is required and not set
		if contextDef.Required != nil && *contextDef.Required && values[k] == nil {
			errs = append(errs, fmt.Errorf("context value %s is required but not set", k))
		}
	}

	return values, errors.Join(errs...)
}

// VerifySubject performs the core verification of attested data. This step runs after
// all gathering, parsing, transforming and verification is performed.
func (di *defaultIplementation) VerifySubject(
	ctx context.Context, opts *VerificationOptions, evaluators map[class.Class]evaluator.Evaluator,
	p *papi.Policy, evalContextValues map[string]any, subject attestation.Subject, predicates []attestation.Predicate,
) (*papi.Result, error) {
	evalContextValuesStruct, err := structpb.NewStruct(evalContextValues)
	if err != nil {
		return nil, fmt.Errorf("serializing evaluation context data: %w", err)
	}
	rs := &papi.Result{
		DateStart: timestamppb.Now(),
		Policy: &papi.PolicyRef{
			Id: p.Id,
		},
		Meta: p.GetMeta(),
		Subject: &gointoto.ResourceDescriptor{
			Name:   subject.GetName(),
			Uri:    subject.GetUri(),
			Digest: subject.GetDigest(),
		},
		Context: evalContextValuesStruct,
	}

	evalOpts := &options.EvaluatorOptions{}

	errs := []error{}
	for i, tenet := range p.Tenets {
		key := class.Class(tenet.Runtime)
		if key == "" {
			key = class.Class("default")
		}

		// Populate the context data
		ctx := context.WithValue(
			ctx, evalcontext.EvaluationContextKey{},
			evalcontext.EvaluationContext{
				Subject:       subject,
				Policy:        p,
				ContextValues: evalContextValues,
			},
		)

		// Filter the predicates to those requested by the tenet or the policy:
		npredicates := []attestation.Predicate{}
		idx := map[attestation.PredicateType]struct{}{}

		// If the tenet has a set of predicate types defined, it supersedes
		// those defined at the policy level:
		if len(tenet.GetPredicates().GetTypes()) > 0 {
			for _, tp := range tenet.GetPredicates().GetTypes() {
				idx[attestation.PredicateType(tp)] = struct{}{}
			}
		} else {
			// Tenet has no predicate types defined, filter using the policy types
			for _, tp := range p.GetPredicates().GetTypes() {
				idx[attestation.PredicateType(tp)] = struct{}{}
			}
		}

		for _, pred := range predicates {
			if _, ok := idx[pred.GetType()]; ok {
				npredicates = append(npredicates, pred)
			}
		}

		evalres, err := evaluators[key].ExecTenet(ctx, evalOpts, tenet, npredicates)
		if err != nil {
			errs = append(errs, fmt.Errorf("executing tenet #%d: %w", i, err))
			continue
		}
		logrus.WithField("tenet", i).Debugf("Result: %+v", evalres)

		// Ideally, we should not reach here with unparseabke templates but oh well..

		// This is the data that gets exposed to error and assessment templates
		templateData := struct {
			Context map[string]any
			Outputs map[string]any
		}{
			Context: evalContextValues,
			Outputs: evalres.GetOutput().AsMap(),
		}

		// Carry over the error from the policy if the runtime didn't add one
		if evalres.Status != papi.StatusPASS && evalres.Error == nil {
			var b, b2 bytes.Buffer

			tmplMsg, err := template.New("error_message").Parse(tenet.Error.GetMessage())
			if err != nil {
				return nil, fmt.Errorf("parsing tenet error template: %w", err)
			}
			if err := tmplMsg.Execute(&b, templateData); err != nil {
				return nil, fmt.Errorf("executing error message template: %w", err)
			}

			tmpl, err := template.New("error_guidance").Parse(tenet.Error.GetGuidance())
			if err != nil {
				return nil, fmt.Errorf("parsing tenet guidance template: %w", err)
			}
			if err := tmpl.Execute(&b2, templateData); err != nil {
				return nil, fmt.Errorf("executing error guidance template: %w", err)
			}

			evalres.Error = &papi.Error{
				Message:  b.String(),
				Guidance: b2.String(),
			}
		}

		// Carry over the assessment from the policy if not set by the runtime
		if evalres.Status == papi.StatusPASS && evalres.Assessment == nil {
			tmpl, err := template.New("assessment").Parse(tenet.Assessment.GetMessage())
			if err != nil {
				return nil, fmt.Errorf("parsing tenet assessment: %w", err)
			}
			var b bytes.Buffer
			if err := tmpl.Execute(&b, templateData); err != nil {
				return nil, fmt.Errorf("executing assessment template: %w", err)
			}
			evalres.Assessment = &papi.Assessment{
				Message: b.String(),
			}
		}

		rs.EvalResults = append(rs.EvalResults, evalres)
	}

	// Stamp the end date
	rs.DateEnd = timestamppb.Now()

	return rs, errors.Join(errs...)
}

// AttestResults writes an attestation captring the evaluation
// results set.
func (di *defaultIplementation) AttestResults(
	ctx context.Context, opts *VerificationOptions, results papi.Results,
) error {
	if !opts.AttestResults {
		return nil
	}

	logrus.Debugf("writing evaluation attestation to %s", opts.ResultsAttestationPath)

	// Open the file in the options
	f, err := os.Create(opts.ResultsAttestationPath)
	if err != nil {
		return fmt.Errorf("opening results attestation file: %w", err)
	}

	switch r := results.(type) {
	case *papi.Result:
		// Write the statement to json
		return di.AttestResultToWriter(f, r)
	case *papi.ResultSet:
		return di.AttestResultSetToWriter(f, r)
	default:
		return fmt.Errorf("unable to cast result")
	}
}

// AttestResultToWriter writes an attestation capturing a evaluation
// result set.
func (di *defaultIplementation) AttestResultToWriter(
	w io.Writer, result *papi.Result,
) error {
	if result == nil {
		return fmt.Errorf("unable to attest results, set is nil")
	}

	subject := result.Subject
	if result.Chain != nil {
		if len(result.Chain) > 0 {
			subject = result.Chain[0].Source
		}
	}

	// Create the predicate file
	pred := ampelPred.NewPredicate()
	pred.Parsed = &papi.ResultSet{
		Results: []*papi.Result{result},
	}

	// Create the statement
	stmt := intoto.NewStatement()
	stmt.PredicateType = ampelPred.PredicateTypeResults
	stmt.AddSubject(subject)
	stmt.Predicate = pred

	// Write the statement to json
	return stmt.WriteJson(w)
}

func stringifyDigests(subject attestation.Subject) string {
	s := []string{}
	for algo, val := range subject.GetDigest() {
		s = append(s, fmt.Sprintf("%s:%s", algo, val))
	}

	slices.Sort(s)
	return strings.Join(s, "/")
}

// AttestResults writes an attestation captring the evaluation
// results set.
func (di *defaultIplementation) AttestResultSetToWriter(
	w io.Writer, resultset *papi.ResultSet,
) error {
	if resultset == nil {
		return fmt.Errorf("unable to attest results, set is nil")
	}

	// TODO(puerco): This should probably be a method of the results set
	seen := []string{}

	// Create the statement
	stmt := intoto.NewStatement()

	for _, result := range resultset.Results {
		subject := result.Subject
		if result.Chain != nil {
			if len(result.Chain) > 0 {
				subject = result.Chain[0].Source
			}
		}

		// If we already saw it, next:
		if slices.Contains(seen, stringifyDigests(subject)) {
			continue
		}

		// If we havent check if we have a matching pred
		seen = append(seen, stringifyDigests(subject))
		haveMatching := false
		for _, s := range stmt.Subject {
			if attestation.SubjectsMatch(s, subject) {
				haveMatching = true
				break
			}
		}
		if !haveMatching {
			stmt.AddSubject(subject)
		}
	}

	// Create the predicate file
	pred := ampelPred.NewPredicate()
	pred.Parsed = resultset

	stmt.PredicateType = ampelPred.PredicateTypeResults
	stmt.Predicate = pred

	// Write the statement to json
	return stmt.WriteJson(w)
}

// ProcessPolicySetChainedSubjects executes a PolicySet's ChainLink and returns
// the resulting list of subjects from the evaluator.
func (di *defaultIplementation) ProcessPolicySetChainedSubjects(
	ctx context.Context, opts *VerificationOptions, evaluators map[class.Class]evaluator.Evaluator,
	agent *collector.Agent, policySet *papi.PolicySet, evalContextValues map[string]any, subject attestation.Subject,
	attestations []attestation.Envelope,
) ([]attestation.Subject, []*papi.ChainedSubject, bool, error) {
	chain := []*papi.ChainedSubject{}

	// If there are no chained subjects, then the list of subject contains only
	// the original subject. If there is a chain defined, then the subject will
	// be replaced with the list of data extracted from the chain's attesations.
	if policySet.GetChain() == nil {
		return []attestation.Subject{subject}, chain, false, nil
	}

	// Get the default evaluator from the policy
	defaultEvalClass := ""
	if policySet.GetMeta() != nil {
		defaultEvalClass = policySet.GetMeta().GetRuntime()
	}

	subjects, chain, fail, err := di.evaluateChain(
		ctx, opts, evaluators, agent, policySet.GetChain(), evalContextValues, subject,
		attestations, policySet.GetCommon().GetIdentities(), defaultEvalClass,
	)
	if err != nil {
		return nil, nil, false, err
	}

	if len(subjects) == 0 {
		return nil, nil, false, fmt.Errorf("unable to complete evidence chain, no subject returned")
	}

	return subjects, chain, fail, nil
}
