package cel

import (
	"context"
	"fmt"

	api "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/evaluator/options"
)

// New creates a new CEL evaluator with the default options
func New() *Evaluator {
	return &Evaluator{
		impl: &defaulCelEvaluator{},
	}
}

// Evaluator implements the evaluator.Evaluator interface to evaluate CEL code
type Evaluator struct {
	impl CelEvaluatorImplementation
}

// Exec executes each tenet and returns the combined results
func (e *Evaluator) Exec(
	ctx context.Context, opts options.Options, tenet *api.Tenet, predicates []attestation.Predicate,
) (*api.ResultSet, error) {
	// Create the evaluation enviroment
	env, err := e.impl.CreateEnvironment()
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	// Compile the tenet code into ASTs
	asts, err := e.impl.CompileTenets(env, []*api.Tenet{tenet})
	if err != nil {
		return nil, fmt.Errorf("compiling program: %w", err)
	}

	// Evaluate the asts and compile the results into a resultset
	resultset, err := e.impl.Evaluate(asts)
	if err != nil {
		return nil, fmt.Errorf("evaluating ASTs: %w", err)
	}

	return resultset, err
}
