// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/collector"
	"github.com/carabiner-dev/ampel/pkg/evaluator"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/evalcontext"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
	"github.com/carabiner-dev/ampel/pkg/filters"
	"github.com/carabiner-dev/ampel/pkg/formats/envelope"
	ampelPred "github.com/carabiner-dev/ampel/pkg/formats/predicate/ampel"
	"github.com/carabiner-dev/ampel/pkg/formats/statement/intoto"
	"github.com/carabiner-dev/ampel/pkg/transformer"
)

// AmpelImplementation
type AmpelVerifier interface {
	GatherAttestations(context.Context, *VerificationOptions, *collector.Agent, *api.Policy, attestation.Subject, []attestation.Envelope) ([]attestation.Envelope, error)
	ParseAttestations(context.Context, []string) ([]attestation.Envelope, error)
	BuildEvaluators(*VerificationOptions, *api.Policy) (map[class.Class]evaluator.Evaluator, error)
	BuildTransformers(*VerificationOptions, *api.Policy) (map[transformer.Class]transformer.Transformer, error)
	Transform(*VerificationOptions, map[transformer.Class]transformer.Transformer, *api.Policy, attestation.Subject, []attestation.Predicate) (attestation.Subject, []attestation.Predicate, error)

	// CheckIdentities verifies that attestations are signed by the policy identities
	CheckIdentities(*VerificationOptions, []*api.Identity, []attestation.Envelope) (bool, []error, error)

	FilterAttestations(*VerificationOptions, attestation.Subject, []attestation.Envelope) ([]attestation.Predicate, error)
	AssertResult(*api.Policy, *api.Result) error
	AttestResult(context.Context, *VerificationOptions, *api.Result) error

	// AttestResultToWriter takes an evaluation result and writes an attestation to the supplied io.Writer
	AttestResultToWriter(io.Writer, *api.Result) error

	// AttestResultSetToWriter takes an policy resultset and writes an attestation to the supplied io.Writer
	AttestResultSetToWriter(io.Writer, *api.ResultSet) error

	// VerifySubject runs the verification process.
	VerifySubject(context.Context, *VerificationOptions, map[class.Class]evaluator.Evaluator, *api.Policy, map[string]any, attestation.Subject, []attestation.Predicate) (*api.Result, error)

	// ProcessChainedSubjects proceses the chain of attestations to find the ultimate
	// subject a policy is supposed to operate on
	ProcessChainedSubjects(context.Context, *VerificationOptions, map[class.Class]evaluator.Evaluator, *collector.Agent, *api.Policy, map[string]any, attestation.Subject, []attestation.Envelope) (attestation.Subject, []*api.ChainedSubject, bool, error)

	// AssemblePolicyEvalContext builds the policy context by mixing defaults and defined values
	AssemblePolicyEvalContext(context.Context, *VerificationOptions, *api.Policy) (map[string]any, error)
}

type defaultIplementation struct{}

// GatherAttestations assembles the attestations pack required to run the
// evaluation. It first filters the attestations loaded manually by matching
// their descriptors against the chained subject and keeping those without
// a subject.
func (di *defaultIplementation) GatherAttestations(
	ctx context.Context, opts *VerificationOptions, agent *collector.Agent,
	policy *api.Policy, subject attestation.Subject, attestations []attestation.Envelope,
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
func (di *defaultIplementation) AssertResult(policy *api.Policy, result *api.Result) error {
	switch policy.GetMeta().GetAssertMode() {
	case "OR", "":
		for _, er := range result.EvalResults {
			if er.Status == api.StatusPASS {
				result.Status = api.StatusPASS
				return nil
			}
		}
		result.Status = api.StatusFAIL
		if policy.Meta.Enforce == "OFF" {
			result.Status = api.StatusSOFTFAIL
		}
	case "AND":
		for _, er := range result.EvalResults {
			if er.Status == api.StatusFAIL {
				result.Status = api.StatusFAIL
				if policy.Meta.Enforce == "OFF" {
					result.Status = api.StatusSOFTFAIL
				}
				return nil
			}
		}
		result.Status = api.StatusPASS
	default:
		return fmt.Errorf("invalid policy assertion mode")
	}
	return nil
}

// BuildEvaluators checks a policy and build the required evaluators to run the tenets
func (di *defaultIplementation) BuildEvaluators(opts *VerificationOptions, p *api.Policy) (map[class.Class]evaluator.Evaluator, error) {
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
func (di *defaultIplementation) BuildTransformers(opts *VerificationOptions, policy *api.Policy) (map[transformer.Class]transformer.Transformer, error) {
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
	policy *api.Policy, subject attestation.Subject, predicates []attestation.Predicate,
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
// identities defined in thew policy.
func (di *defaultIplementation) CheckIdentities(_ *VerificationOptions, identities []*api.Identity, envelopes []attestation.Envelope) (bool, []error, error) {
	// verification errors for the user
	errs := make([]error, len(envelopes))

	// If there are no identities defined, return here
	if len(identities) == 0 {
		logrus.Debug("No identities defined in policy. Not checking.")
		return true, nil, nil
	} else {
		logrus.Debug("Will look for signed attestations from:")
		for _, i := range identities {
			logrus.Debugf("  > %s", i.Slug())
		}
	}

	validIdentities := true

	// First, verify the signatures on the envelopes
	for i, e := range envelopes {
		// Attestations are expected to be verified here already, but we want
		// to make sure. This should not be an issue as the verification data
		// should be already cached.
		if err := e.Verify(); err != nil {
			errs[i] = fmt.Errorf("verifying attestation signature: %w", err)
			validIdentities = false
			continue
		}

		validSigners := []*api.Identity{}
		if e.GetVerification() == nil {
			errs[i] = errors.New("attestation not verified")
			validIdentities = false
			continue
		}

		for _, id := range identities {
			if e.GetVerification().MatchesIdentity(id) {
				validSigners = append(validSigners, id)
			}
		}

		if len(validSigners) == 0 {
			validIdentities = false
			errs[i] = fmt.Errorf("attestation %d (type %s) has no recognized signer identities", i, e.GetStatement().GetType())
		}
	}

	// We don't use the errors yet, but at some point we should embed them into
	// the attestation verification.
	return validIdentities, errs, nil
}

func (di *defaultIplementation) FilterAttestations(opts *VerificationOptions, subject attestation.Subject, envs []attestation.Envelope) ([]attestation.Predicate, error) {
	preds := []attestation.Predicate{}
	for _, env := range envs {
		preds = append(preds, env.GetStatement().GetPredicate())
	}
	return preds, nil
}

// SelectChainedSubject returns a new subkect from an ingested attestatom
func (di *defaultIplementation) ProcessChainedSubjects(
	ctx context.Context, opts *VerificationOptions, evaluators map[class.Class]evaluator.Evaluator,
	agent *collector.Agent, policy *api.Policy, evalContextValues map[string]any, subject attestation.Subject,
	attestations []attestation.Envelope,
) (attestation.Subject, []*api.ChainedSubject, bool, error) {
	chain := []*api.ChainedSubject{}
	// If there are no chained subjects, return the original
	if policy.GetChain() == nil {
		return subject, chain, false, nil
	}

	logrus.Debug("Processing evidence chain")
	for i, link := range policy.GetChain() {
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

		for _, a := range attestations {
			if err := a.Verify(); err != nil {
				return nil, nil, true, PolicyError{
					error:    fmt.Errorf("signature verifying failed in chained subject: %w", err),
					Guidance: "the signature verification in the loaded attestations failed, try resigning it",
				}
			}
		}
		var pass bool
		var err error
		if link.GetPredicate().GetIdentities() != nil {
			pass, _, err = di.CheckIdentities(opts, link.GetPredicate().GetIdentities(), attestations)
		} else {
			pass, _, err = di.CheckIdentities(opts, policy.GetIdentities(), attestations)
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
		if classString == "" && policy.GetMeta() != nil {
			classString = policy.GetMeta().GetRuntime()
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
			fmt.Printf("Evals: %+v\n", evaluators)
			return nil, nil, false, fmt.Errorf("no evaluator loaded for class %s", key)
		}

		// Populate the context data
		ctx := context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalcontext.EvaluationContext{
			Subject:       subject,
			Policy:        policy,
			ContextValues: evalContextValues,
		})
		// Execute the selector
		newsubject, err := evaluators[key].ExecChainedSelector(
			ctx, &opts.EvaluatorOptions, link.GetPredicate(),
			attestations[0].GetStatement().GetPredicate(),
		)
		if err != nil {
			// TODO(puerco): The false here instructs ampel to return an error
			// (not a policy fail) when there is a syntax error in the policy
			// code (CEL or otherwise). Perhaps this shoul be configured
			return nil, nil, false, fmt.Errorf("evaluating chained subject code: %w", err)
		}

		// Add to link history
		chain = append(chain, &api.ChainedSubject{
			Source:      api.NewResourceDescriptor().FromSubject(subject),
			Destination: api.NewResourceDescriptor().FromSubject(newsubject),
			Link: &api.ChainedSubjectLink{
				Type:        string(attestations[0].GetStatement().GetPredicateType()),
				Attestation: api.NewResourceDescriptor().FromSubject(attestations[0].GetStatement().GetPredicate().GetSource()),
			},
		})
		subject = newsubject
	}
	return subject, chain, false, nil
}

// AssemblePolicyEvalContext puts together the context.
func (di *defaultIplementation) AssemblePolicyEvalContext(ctx context.Context, opts *VerificationOptions, p *api.Policy) (map[string]any, error) {
	errs := []error{}

	// Load the context definitions as received from invocation
	definitions := map[string]any{}
	values := map[string]any{}
	assembledContext := map[string]*api.ContextVal{}

	// Things using AMPEL send the definitions in the context
	preContext, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if ok {
		if preContext.ContextValues != nil {
			definitions = preContext.ContextValues
		}

		// Assemble the context structure from the struct received from ancestors
		// (eg if its coming from a PolicySet commons)
		if preContext.Context != nil {
			assembledContext = preContext.Context
		}
	}

	// Override the ancestor context structure with the policy (if any)
	for k, def := range p.GetContext() {
		if _, ok := assembledContext[k]; ok {
			assembledContext[k].Merge(def)
		} else {
			assembledContext[k] = def
		}
	}

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
	p *api.Policy, evalContextValues map[string]any, subject attestation.Subject, predicates []attestation.Predicate,
) (*api.Result, error) {
	evalContextValuesStruct, err := structpb.NewStruct(evalContextValues)
	if err != nil {
		return nil, fmt.Errorf("serializing evaluation context data: %w", err)
	}
	rs := &api.Result{
		DateStart: timestamppb.Now(),
		Policy: &api.PolicyRef{
			Id: p.Id,
		},
		Meta: p.GetMeta(),
		Subject: &api.ResourceDescriptor{
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

		// Carry over the error from the policy if the evaluator didn't add one
		if evalres.Status != api.StatusPASS && evalres.Error == nil {
			evalres.Error = tenet.Error
		}

		// Carry over the assessment from the policy of not set by the engine
		if evalres.Status == api.StatusPASS && evalres.Assessment == nil {
			evalres.Assessment = tenet.Assessment
		}

		rs.EvalResults = append(rs.EvalResults, evalres)
	}

	// Stamp the end date
	rs.DateEnd = timestamppb.Now()

	return rs, errors.Join(errs...)
}

// AttestResults writes an attestation captring the evaluation
// results set.
func (di *defaultIplementation) AttestResult(
	ctx context.Context, opts *VerificationOptions, result *api.Result,
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

	// Write the statement to json
	return di.AttestResultToWriter(f, result)
}

// AttestResults writes an attestation captring the evaluation
// results set.
func (di *defaultIplementation) AttestResultToWriter(
	w io.Writer, result *api.Result,
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
	pred.Parsed = &api.ResultSet{
		Results: []*api.Result{result},
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
	w io.Writer, resultset *api.ResultSet,
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
