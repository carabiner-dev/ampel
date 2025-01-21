package cel

import (
	"context"
	"fmt"

	"github.com/google/cel-go/cel"
	api "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/evaluator/options"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	VarNamePredicates = "predicates"
	VarNameContext    = "context"
)

// New creates a new CEL evaluator with the default options
func New(opts *options.EvaluatorOptions) (*Evaluator, error) {
	impl := &defaulCelEvaluator{}

	// Create the evaluation enviroment
	env, err := impl.CreateEnvironment(opts)
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	return &Evaluator{
		Environment: env,
		impl:        &defaulCelEvaluator{},
	}, nil
}

// Evaluator implements the evaluator.Evaluator interface to evaluate CEL code
type Evaluator struct {
	Environment *cel.Env
	impl        CelEvaluatorImplementation
}

// Exec executes each tenet and returns the combined results
func (e *Evaluator) ExecTenet(
	ctx context.Context, opts *options.EvaluatorOptions, tenet *api.Tenet, predicates []attestation.Predicate,
) (*api.EvalResult, error) {
	// Compile the tenet code into ASTs
	ast, err := e.impl.CompileCode(e.Environment, tenet.Code)
	if err != nil {
		return nil, fmt.Errorf("compiling program: %w", err)
	}

	outputAsts := map[string]*cel.Ast{}
	for id, output := range tenet.Outputs {
		oast, err := e.impl.CompileCode(e.Environment, output.Code)
		if err != nil {
			return nil, fmt.Errorf("compiling output #%s: %w", id, err)
		}
		outputAsts[id] = oast
	}

	vars, err := e.impl.BuildVariables(opts, tenet, predicates)
	if err != nil {
		return nil, fmt.Errorf("building variables for eval environment: %w", err)
	}

	outputMap, err := e.impl.EvaluateOutputs(e.Environment, outputAsts, vars)
	if err != nil {
		return nil, fmt.Errorf("evaluating outputs: %w", err)
	}

	// Evaluate the asts and compile the results into a resultset
	result, err := e.impl.Evaluate(e.Environment, ast, vars)
	if err != nil {
		return nil, fmt.Errorf("evaluating ASTs: %w", err)
	}

	outStruct, err := structpb.NewStruct(outputMap)
	if err != nil {
		return nil, fmt.Errorf("converting outputs to struct: %w", err)
	}
	result.Output = outStruct
	// result.Output = []*api.Output{}
	// for _, o := range tenet.Outputs {
	// 	val, err := structpb.NewValue(outputMap[o.Id])
	// 	if err != nil {
	// 		return nil, fmt.Errorf("generating value from +%v: %w", outputMap[o.Id], err)
	// 	}
	// 	result.Output = append(result.Output, &api.Output{
	// 		Id:    o.Id,
	// 		Type:  o.Type,
	// 		Code:  o.Code,
	// 		Value: val,
	// 	})
	// }

	return result, err
}
