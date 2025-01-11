package cel

import (
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	v1 "github.com/puerco/ampel/pkg/api/v1"
)

type CelEvaluatorImplementation interface {
	CompileTenets(*cel.Env, []*v1.Tenet) ([]*cel.Ast, error)
	CreateEnvironment() (*cel.Env, error)
	Evaluate([]*cel.Ast) (*v1.ResultSet, error)
	Assert(*v1.ResultSet) bool
}

type defaulCelEvaluator struct{}

// compileTenets compiles the CEL code from the teenets into their syntax trees.
func (dce *defaulCelEvaluator) CompileTenets(env *cel.Env, tenets []*v1.Tenet) ([]*cel.Ast, error) {
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

// CreateEnvironment
func (dce *defaulCelEvaluator) CreateEnvironment() (*cel.Env, error) {
	envOpts := []cel.EnvOption{
		// cel.CustomTypeAdapter(&customTypeAdapter{}),
		//Library(),
		ext.Bindings(),
		ext.Strings(),
		ext.Encoders(),
		// cel.Types(elements.DocumentType),
	}

	// Add any additional environment options passed in the construcutor
	envOpts = append(envOpts, buildEnv()...)

	env, err := cel.NewEnv(
		envOpts...,
	)
	if err != nil {
		return nil, (fmt.Errorf("creating CEL environment: %w", err))
	}

	return env, nil
}

// Evaluate
func (dce *defaulCelEvaluator) Evaluate([]*cel.Ast) (*v1.ResultSet, error) {
	return nil, nil
}

func (dce *defaulCelEvaluator) Assert(*v1.ResultSet) bool {
	return false
}
