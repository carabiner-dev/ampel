package verifier

import (
	api "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/collector"
	"github.com/puerco/ampel/pkg/evaluator"
	"github.com/puerco/ampel/pkg/evaluator/options"
)

type VerificationOptions struct {
	// Embed the evaluator options
	options.EvaluatorOptions

	// Collectors is a collection of configured attestation fetchers
	Collectors []collector.AttestationFetcher

	// AttestationFiles are additional attestations passed manually
	AttestationFiles []string

	// DefaultEvaluator is the default evaluator we use when a policy does
	// not define one.
	DefaultEvaluator evaluator.Class

	// AttestResults will generate an attestation of the evaluation results
	AttestResults bool

	// ResultsAttestationPath stores the path to write the results attestation
	ResultsAttestationPath string
}

var DefaultVerificationOptions = VerificationOptions{
	EvaluatorOptions: options.EvaluatorOptions{
		Context: &api.Context{},
	},

	// DefaultEvaluator the the default eval enfine is the lowest version
	// of CEL available
	DefaultEvaluator: evaluator.Class("cel@v1.0.0"),

	// ResultsAttestationPath path to the results attestation
	ResultsAttestationPath: "results.intoto.json",
}

func NewVerificationOptions() VerificationOptions {
	return DefaultVerificationOptions
}
