package cel

import (
	"context"
	"fmt"

	api "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/evaluator/options"
)

const (
	VarNamePredicates = "predicates"
	VarNameContext    = "context"
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
func (e *Evaluator) ExecTenet(
	ctx context.Context, opts *options.Options, tenet *api.Tenet, predicates []attestation.Predicate,
) (*api.Result, error) {
	// Create the evaluation enviroment
	env, err := e.impl.CreateEnvironment(opts)
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	// Compile the tenet code into ASTs
	ast, err := e.impl.CompileTenet(env, tenet)
	if err != nil {
		return nil, fmt.Errorf("compiling program: %w", err)
	}

	vars, err := e.impl.BuildVariables(opts, tenet, predicates)
	if err != nil {
		return nil, fmt.Errorf("building variables for eval environment: %w", err)
	}

	// Evaluate the asts and compile the results into a resultset
	result, err := e.impl.Evaluate(env, ast, vars)
	if err != nil {
		return nil, fmt.Errorf("evaluating ASTs: %w", err)
	}

	return result, err
}
