package verifier

import (
	"context"
	"errors"
	"fmt"
	"os"

	api "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/evaluator"
	"github.com/puerco/ampel/pkg/formats/envelope"
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

// AssertResults conducts the final assertion to allow/block based on the
// result sets returned by the evaluators.
func (di *defaultIplementation) AssertResults([]*api.ResultSet) (bool, error) {
	return true, nil
}

// BuildEvaluators checks a policy and build the required evaluators to run the tenets
func (di *defaultIplementation) BuildEvaluators(opts *VerificationOptions, p *api.Policy) (map[evaluator.Class]evaluator.Evaluator, error) {
	evaluators := map[evaluator.Class]evaluator.Evaluator{}
	factory := evaluator.Factory{}
	// First, build the default evaluator
	def := p.Runtime
	if p.Runtime == "" {
		def = "cel/1"
	}
	e, err := factory.Get(evaluator.Class(def))
	if err != nil {
		return nil, fmt.Errorf("unable to build default runtime")
	}
	evaluators[evaluator.Class("default")] = e

	for _, t := range p.Tenets {
		if t.Runtime != "" {
			cl := evaluator.Class(t.Runtime)
			if _, ok := evaluators[cl]; ok {
				continue
			}
			e, err := factory.Get(cl)
			if err != nil {
				return nil, fmt.Errorf("building %q runtime: %w", t.Runtime, err)
			}
			evaluators[cl] = e
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
		predicates, err = t.Default(predicates)
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

// VerifySubject
func (di *defaultIplementation) VerifySubject(
	opts *VerificationOptions, evaluators map[evaluator.Class]evaluator.Evaluator,
	p *api.Policy, subject attestation.Subject, predicates []attestation.Predicate,
) (*api.ResultSet, error) {
	rs := &api.ResultSet{
		Results: []*api.Result{},
	}

	return rs, nil
}
