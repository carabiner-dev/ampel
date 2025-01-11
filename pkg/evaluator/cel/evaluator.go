package cel

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	v1 "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/evaluator/options"
)

type Evaluator struct {
}

// compileTenets compiles the CEL code from the teenets into their syntax trees.
func (e *Evaluator) compileTenets(env *cel.Env, tenets []*v1.Tenet) ([]*cel.Ast, error) {
	// Compile the tenets into their ASTs
	var asts = []*cel.Ast{}
	var errs = []error{}

	for i, t := range tenets {
		ast, iss := env.Compile(t.Code)
		if iss.Err() != nil {
			return nil, fmt.Errorf("compilation error on tenet #%d: %w", i, iss.Err())
		}
		asts = append(asts, ast)
	}

	return asts, errors.Join(errs...)
}

func buildEnv() []cel.EnvOption {
	return []cel.EnvOption{}
}

func createEnvironment() (*cel.Env, error) {
	envOpts := []cel.EnvOption{
		// cel.CustomTypeAdapter(&customTypeAdapter{}),
		//Library(),
		ext.Bindings(),
		ext.Strings(),
		ext.Encoders(),
		// cel.Types(elements.DocumentType),
	}

	// Add any additional environment options passed in the construcutor
	// envOpts = append(envOpts, opts.EnvOptions...)
	env, err := cel.NewEnv(
		envOpts...,
	)
	if err != nil {
		return nil, (fmt.Errorf("creating CEL environment: %w", err))
	}

	return env, nil
}

func (e *Evaluator) Evaluate([]*cel.Ast) (*v1.ResultSet, error) {
	return nil, nil
}

func (e *Evaluator) Assert(*v1.ResultSet) bool {
	return false
}

// Exec executes each tenet and returns the combined results
func (e *Evaluator) Exec(
	ctx context.Context, opts options.Options, tenets []*v1.Tenet, statements []*attestation.Statement,
) (bool, *v1.ResultSet, error) {

	env, err := createEnvironment()
	if err != nil {
		return false, nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	asts, err := e.compileTenets(env, tenets)
	if err != nil {
		return false, nil, fmt.Errorf("compiling program: %w", err)
	}

	resultset, err := e.Evaluate(asts)
	if err != nil {
		return false, nil, fmt.Errorf("evaluating ASTs: %w", err)
	}

	return e.Assert(resultset), resultset, nil
}
