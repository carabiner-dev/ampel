package verifier

import (
	"context"
	"errors"
	"fmt"

	api "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/collector"
	"github.com/puerco/ampel/pkg/evaluator"
	"github.com/puerco/ampel/pkg/transformer"
)

// AmpelImplementation
type AmpelImplementation interface {
	GatherAttestations(context.Context, *VerificationOptions, attestation.Subject) ([]attestation.Envelope, error)
	ParseAttestations(context.Context, []string) ([]attestation.Envelope, error)
	BuildEvaluators(*VerificationOptions, *api.Policy) (map[evaluator.Class]evaluator.Evaluator, error)
	BuildTransformers(*VerificationOptions, *api.Policy) (map[transformer.Class]transformer.Transformer, error)
	Transform(*VerificationOptions, map[transformer.Class]transformer.Transformer, *api.Policy, []attestation.Predicate) ([]attestation.Predicate, error)
	CheckIdentities(*VerificationOptions, *api.Policy, []attestation.Envelope) error
	FilterAttestations(*VerificationOptions, attestation.Subject, []attestation.Envelope) ([]attestation.Predicate, error)
	AssertResults([]*api.ResultSet) (bool, error)
	VerifySubject(*VerificationOptions, map[evaluator.Class]evaluator.Evaluator, *api.Policy, attestation.Subject, []attestation.Predicate) (*api.ResultSet, error)
}

func New() (*Ampel, error) {
	return &Ampel{
		impl: &defaultIplementation{},
	}, nil
}

// Ampel is the attestation verifier
type Ampel struct {
	impl AmpelImplementation
}

type VerificationOptions struct {
	// Collectors is a collection of configured attestation fetchers
	Collectors []collector.AttestationFetcher

	// AttestationFiles are additional attestations passed manually
	AttestationFiles []string

	// DefaultEvaluator is the default evaluator we use when a policy does
	// not define one.
	DefaultEvaluator evaluator.Class
}

var defaultVerificationOptions = VerificationOptions{
	// DefaultEvaluator the the default eval enfine is the lowest version
	// of CEL available
	DefaultEvaluator: evaluator.Class("cel/1"),
}

func NewVerificationOptions() *VerificationOptions {
	return &VerificationOptions{
		Collectors:       []collector.AttestationFetcher{},
		AttestationFiles: []string{},
		DefaultEvaluator: defaultVerificationOptions.DefaultEvaluator,
	}
}

// Verify checks a number of subjects against a policy using the available evidence
func (ampel *Ampel) Verify(
	ctx context.Context, opts *VerificationOptions, policy *api.Policy, subject attestation.Subject,
) (*api.ResultSet, error) {
	// Fetch applicable evidence
	atts, err := ampel.impl.GatherAttestations(ctx, opts, subject)
	if err != nil {
		return nil, fmt.Errorf("gathering evidence: %w", err)
	}

	// Parse any extra files defined in the options
	moreatts, err := ampel.impl.ParseAttestations(ctx, opts.AttestationFiles)
	if err != nil {
		return nil, fmt.Errorf("parsing files: %w", err)
	}
	atts = append(atts, moreatts...)

	// Here, the policy may not require attestations (noop) but it's a corner
	// case, we'll fix it later.
	if len(atts) == 0 {
		return nil, errors.New("no evidence found to evaluate policy")
	}

	// Check identities to see if the attestations can be admitted
	// TODO(puerco)
	// Option: Unmatched identities cause a:fail or b:ignore
	if err := ampel.impl.CheckIdentities(opts, policy, atts); err != nil {
		return nil, fmt.Errorf("admission failed: %w", err)
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

	// Apply the defined tranformations to the predicates
	preds, err = ampel.impl.Transform(opts, transformers, policy, preds)
	if err != nil {
		return nil, fmt.Errorf("applying transformations: %w", err)
	}

	// Build the required evaluators
	evaluators, err := ampel.impl.BuildEvaluators(opts, policy)
	if err != nil {
		return nil, fmt.Errorf("building evaluators: %w", err)
	}

	// Eval Policy
	results, err := ampel.impl.VerifySubject(opts, evaluators, policy, subject, preds)
	if err != nil {
		return nil, fmt.Errorf("verifying subject: %w", err)
	}

	// Generate outputs
	return results, nil
}
