// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"errors"
	"fmt"
	"os"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/collector"
	"github.com/carabiner-dev/ampel/pkg/evaluator"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
	"github.com/carabiner-dev/ampel/pkg/filters"
	"github.com/carabiner-dev/ampel/pkg/formats/envelope"
	ampelPred "github.com/carabiner-dev/ampel/pkg/formats/predicate/ampel"
	"github.com/carabiner-dev/ampel/pkg/formats/statement/intoto"
	"github.com/carabiner-dev/ampel/pkg/transformer"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type defaultIplementation struct{}

func (di *defaultIplementation) GatherAttestations(ctx context.Context, opts *VerificationOptions, agent *collector.Agent, policy *api.Policy, subject attestation.Subject) ([]attestation.Envelope, error) {
	// TODO: Filter by types and by tenet chains
	res, err := agent.FetchAttestationsBySubject(ctx, []attestation.Subject{subject})
	if err != nil {
		if !errors.Is(err, collector.ErrNoFetcherConfigured) {
			return nil, fmt.Errorf("collecting attestations: %w", err)
		} else {
			logrus.Warn(err)
			return []attestation.Envelope{}, nil
		}
	}
	return res, nil
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
			errs = append(errs, err)
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
	case "AND":
		for _, er := range result.EvalResults {
			if er.Status == api.StatusFAIL {
				result.Status = api.StatusFAIL
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
	def := class.Class(p.GetMeta().Runtime)
	// TODO(puerco): Move this to defaultOptions
	if p.GetMeta().Runtime == "" {
		def = opts.DefaultEvaluator
	} else {
	}

	e, err := factory.Get(&opts.EvaluatorOptions, def)
	if err != nil {
		return nil, fmt.Errorf("unable to build default runtime: %w", err)
	}
	logrus.Debugf("Registered default evaluator of class %s", def)
	evaluators[class.Class("default")] = e
	if p.GetMeta().Runtime != "" {
		evaluators[class.Class(p.GetMeta().Runtime)] = e
	}

	if p.GetChain() != nil && p.GetChain().GetPredicate() != nil {
		if classString := p.GetChain().GetPredicate().GetRuntime(); classString != "" {
			e, err := factory.Get(&opts.EvaluatorOptions, def)
			if err != nil {
				return nil, fmt.Errorf("unable to build chained subject runtime")
			}
			logrus.Debugf("registered evaluator of class %s for chained predicate", classString)
			evaluators[class.Class(classString)] = e
		}
	}

	for _, t := range p.Tenets {
		if t.Runtime != "" {
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
func (di defaultIplementation) Transform(opts *VerificationOptions, transformers map[transformer.Class]transformer.Transformer, policy *api.Policy, predicates []attestation.Predicate) ([]attestation.Predicate, error) {
	var err error
	i := 0
	for _, t := range transformers {
		predicates, err = t.Mutate(predicates)
		if err != nil {
			return nil, fmt.Errorf("applying transformation #%d (%T): %w", i, t, err)
		}
		i++
	}
	ts := []string{}
	for _, s := range predicates {
		ts = append(ts, string(s.GetType()))
	}
	logrus.Debugf("Predicate types after transform: %v", ts)
	return predicates, nil
}

func (di *defaultIplementation) CheckIdentities(_ *VerificationOptions, identities []*api.Identity, envelopes []attestation.Envelope) (bool, error) {
	// If there are no identities defined, return here
	if len(identities) == 0 {
		logrus.Warn("No identities defined in policy. Not checking.")
		return true, nil
	}

	// First, verify the signatures on the envelopes
	for _, e := range envelopes {
		if err := e.Verify(); err != nil {
			return false, fmt.Errorf("verifying attestation signature: %s", err)
		}

		// if !identityAllowed(identities, vr) {
		// 	logrus.Infof("Identity %+v not allowed by policy %+v", vr.SigstoreCertData, identities)
		// 	return false, nil
		// }
	}

	return true, nil
}

// identityAllowed is a temporary stub function to gatye the allowed identitites
func identityAllowed(ids []*api.Identity, vr *attestation.SignatureVerification) bool {
	if vr == nil {
		logrus.Warn("DEMO WARNING: ALLOWING UNSIGNED STATEMENTS")
		return true
	}
	for i := range ids {
		switch {
		case ids[i].Sigstore != nil:
			if ids[i].Sigstore.Identity == vr.SigstoreCertData.SubjectAlternativeName &&
				ids[i].Sigstore.Issuer == vr.SigstoreCertData.Issuer {
				return true
			}
		default:
			// Method not impleented
			logrus.Error("identity type not implemented")
		}
	}
	return false
}

func (di *defaultIplementation) FilterAttestations(opts *VerificationOptions, subject attestation.Subject, envs []attestation.Envelope) ([]attestation.Predicate, error) {
	preds := []attestation.Predicate{}
	for _, env := range envs {
		preds = append(preds, env.GetStatement().GetPredicate())
	}
	return preds, nil
}

// SelectChainedSubject returns a new subkect from an ingested attestatom
func (di defaultIplementation) ProcessChainedSubject(
	ctx context.Context, opts *VerificationOptions, evaluators map[class.Class]evaluator.Evaluator,
	agent *collector.Agent, policy *api.Policy, subject attestation.Subject,
	attestations []attestation.Envelope,
) (attestation.Subject, error) {
	if policy.GetChain() == nil {
		return subject, nil
	}

	if policy.Chain.GetOutput() != nil {
		return nil, fmt.Errorf("chained subjects from outputs are not yet implemented")
	}

	// Build an attestation query for the type we need
	q := attestation.NewQuery().WithFilter(
		&filters.PredicateTypeMatcher{
			PredicateTypes: map[attestation.PredicateType]struct{}{
				attestation.PredicateType(policy.Chain.GetPredicate().GetType()): {},
			},
		},
	)

	if len(attestations) > 0 {
		attestations = q.Run(attestations)
	}

	// Only fetch more atts if needed:
	if len(attestations) == 0 {
		moreatts, err := agent.FetchAttestationsBySubject(
			ctx, []attestation.Subject{subject}, collector.WithQuery(q),
		)
		if err != nil {
			return nil, fmt.Errorf("collecting attestations: %w", err)
		}
		attestations = append(attestations, moreatts...)
	}

	if len(attestations) == 0 {
		return nil, fmt.Errorf("no attestations available to read the chained subject")
	}

	for _, a := range attestations {
		if err := a.Verify(); err != nil {
			return nil, fmt.Errorf("verifying chained attestation: %w", err)
		}
	}
	var pass bool
	var err error
	if policy.Chain.GetPredicate().GetIdentities() != nil {
		pass, err = di.CheckIdentities(opts, policy.Chain.GetPredicate().GetIdentities(), attestations)
	} else {
		pass, err = di.CheckIdentities(opts, policy.GetIdentities(), attestations)
	}
	if !pass {
		return nil, fmt.Errorf("unable to validate chained attestation identity")
	}

	// TODO: Mueve a metodos en policy.go
	classString := policy.Chain.GetPredicate().GetRuntime()
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
		return nil, fmt.Errorf("no evaluator built for %s", key)
	}
	subject, err = evaluators[key].ExecChainedSelector(ctx, &opts.EvaluatorOptions, policy.Chain.GetPredicate(), attestations[0].GetStatement().GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("evaluating chained subject code: %w", err)
	}

	return subject, nil
}

// VerifySubject performs the core verification of attested data. This step runs after
// all gathering, parsing, transforming and verification is performed.
func (di *defaultIplementation) VerifySubject(
	ctx context.Context, opts *VerificationOptions, evaluators map[class.Class]evaluator.Evaluator,
	p *api.Policy, subject attestation.Subject, predicates []attestation.Predicate,
) (*api.Result, error) {
	var rs = &api.Result{
		DateStart: timestamppb.Now(),
		Policy: &api.PolicyRef{
			Id: p.Id,
		},
		Meta: p.Meta,
		Subject: &api.ResourceDescriptor{
			Name:   subject.GetName(),
			Uri:    subject.GetUri(),
			Digest: subject.GetDigest(),
		},
	}

	evalOpts := &options.EvaluatorOptions{
		Context: p.Context,
	}

	var errs = []error{}
	for i, tenet := range p.Tenets {
		key := class.Class(tenet.Runtime)
		if key == "" {
			key = class.Class("default")
		}
		evalres, err := evaluators[key].ExecTenet(ctx, evalOpts, tenet, predicates)
		if err != nil {
			errs = append(errs, fmt.Errorf("executing tenet #%d: %w", i, err))
			continue
		}
		logrus.Debugf("Tenet #%d eval: %+v", i, evalres)

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
	ctx context.Context, opts *VerificationOptions, subject attestation.Subject, result *api.Result,
) error {
	if !opts.AttestResults {
		return nil
	}

	if result == nil {
		return fmt.Errorf("unable to attest results, set is nil")
	}

	logrus.Debugf("writing evaluation attestation to %s", opts.ResultsAttestationPath)

	// Create the predicate file
	pred := ampelPred.NewPredicate()
	pred.Parsed = &api.ResultSet{
		Results: []*api.Result{result},
	}

	// Create the statement
	stmt := intoto.NewStatement()
	stmt.PredicateType = ampelPred.PredicateType
	stmt.AddSubject(subject)
	stmt.Predicate = pred

	// Open the file in the options
	f, err := os.Create(opts.ResultsAttestationPath)
	if err != nil {
		return fmt.Errorf("opening results attestation file: %w", err)
	}

	// Write the statement to json
	return stmt.WriteJson(f)
}
