package verifier

import (
	"context"
	"errors"
	"fmt"

	api "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/evaluator"
	"github.com/puerco/ampel/pkg/transformer"
)

type defaultIplementation struct{}

func (di *defaultIplementation) GatherAttestations(vtx context.Context, opts *VerificationOptions, subject attestation.Subject) ([]attestation.Envelope, error) {
	// TODO: Implement
	return []attestation.Envelope{}, nil
}
func (di *defaultIplementation) ParseAttestations(context.Context, []string) ([]attestation.Envelope, error) {
	// TODO: Implement
	return []attestation.Envelope{}, nil
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
	return transformers, nil
}

// Transform takes the predicates and a set of transformers and applies the transformations
// defined in the policy
func (di defaultIplementation) Transform(opts *VerificationOptions, transformers map[transformer.Class]transformer.Transformer, policy *api.Policy, predicates []attestation.Predicate) ([]attestation.Predicate, error) {
	return []attestation.Predicate{}, nil
}

func (di *defaultIplementation) CheckIdentities(*VerificationOptions, *api.Policy, []attestation.Envelope) error {
	return nil
}

func (di *defaultIplementation) FilterAttestations(*VerificationOptions, attestation.Subject, []attestation.Envelope) ([]attestation.Predicate, error) {
	return nil, nil
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
