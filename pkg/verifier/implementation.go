// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"errors"
	"fmt"
	"os"

	api "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/evaluator"
	"github.com/puerco/ampel/pkg/evaluator/options"
	"github.com/puerco/ampel/pkg/formats/envelope"
	ampelPred "github.com/puerco/ampel/pkg/formats/predicate/ampel"
	"github.com/puerco/ampel/pkg/formats/statement/intoto"
	"github.com/puerco/ampel/pkg/transformer"
	"github.com/sirupsen/logrus"
)

type defaultIplementation struct{}

func (di *defaultIplementation) GatherAttestations(vtx context.Context, opts *VerificationOptions, subject attestation.Subject) ([]attestation.Envelope, error) {
	// TODO: Implement
	return []attestation.Envelope{}, nil
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

		logrus.Infof("parsing %s (%d envelope drivers loaded)", path, len(envelope.Parsers))
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
			if er.Status == "PASSED" {
				result.Status = "PASSED"
				return nil
			}
		}
		result.Status = "FAILED"
	case "AND":
		for _, er := range result.EvalResults {
			if er.Status == "FAILED" {
				result.Status = "FAILED"
				return nil
			}
		}
		result.Status = "PASSED"
	default:
		return fmt.Errorf("invalid policy assertion mode")
	}
	return nil
}

// BuildEvaluators checks a policy and build the required evaluators to run the tenets
func (di *defaultIplementation) BuildEvaluators(opts *VerificationOptions, p *api.Policy) (map[evaluator.Class]evaluator.Evaluator, error) {
	evaluators := map[evaluator.Class]evaluator.Evaluator{}
	factory := evaluator.Factory{}
	// First, build the default evaluator
	def := evaluator.Class(p.GetMeta().Runtime)
	// TODO(puerco): Move this to defaultOptions
	if p.GetMeta().Runtime == "" {
		def = opts.DefaultEvaluator
	}

	e, err := factory.Get(&opts.EvaluatorOptions, def)
	if err != nil {
		return nil, fmt.Errorf("unable to build default runtime")
	}
	logrus.Debugf("Registered default evaluator of class %s", def)
	evaluators[evaluator.Class("default")] = e

	for _, t := range p.Tenets {
		if t.Runtime != "" {
			cl := evaluator.Class(t.Runtime)
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
	logrus.Infof("Loaded %d transformers defined in the policy", len(transformers))
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
	logrus.Infof("Predicate types after tranform: %v", ts)
	return predicates, nil
}

func (di *defaultIplementation) CheckIdentities(*VerificationOptions, *api.Policy, []attestation.Envelope) error {
	return nil
}

func (di *defaultIplementation) FilterAttestations(opts *VerificationOptions, subject attestation.Subject, envs []attestation.Envelope) ([]attestation.Predicate, error) {
	preds := []attestation.Predicate{}
	for _, env := range envs {
		preds = append(preds, env.GetStatement().GetPredicate())
	}
	return preds, nil
}

// VerifySubject performs the core verification of attested data. This step runs after
// all gathering, parsing, transforming and verification is performed.
func (di *defaultIplementation) VerifySubject(
	ctx context.Context, opts *VerificationOptions, evaluators map[evaluator.Class]evaluator.Evaluator,
	p *api.Policy, subject attestation.Subject, predicates []attestation.Predicate,
) (*api.Result, error) {
	var rs = &api.Result{}

	evalOpts := &options.EvaluatorOptions{
		Context: p.Context,
	}

	var errs = []error{}
	for i, tenet := range p.Tenets {
		key := evaluator.Class(tenet.Runtime)
		if key == "" {
			key = evaluator.Class("default")
		}
		evalres, err := evaluators[key].ExecTenet(ctx, evalOpts, tenet, predicates)
		if err != nil {
			errs = append(errs, fmt.Errorf("executing tenet #%d: %w", i, err))
			continue
		}
		logrus.Infof("Tenet #%d eval: %+v", i, evalres)
		rs.EvalResults = append(rs.EvalResults, evalres)
	}

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

	logrus.Infof("writing evaluation attestation to %s", opts.ResultsAttestationPath)

	// Create the predicate file
	pred := ampelPred.NewPredicate()
	pred.Parsed = &api.ResultSet{
		Results: []*api.Result{result},
	}

	// Create the statement
	stmt := intoto.NewStatement()
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
