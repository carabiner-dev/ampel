package cel

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	api "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CelEvaluatorImplementation interface {
	CompileTenet(*cel.Env, *api.Tenet) (*cel.Ast, error)
	CreateEnvironment() (*cel.Env, error)
	BuildVariables([]attestation.Predicate) (*map[string]interface{}, error)
	Evaluate(*cel.Env, *cel.Ast, *map[string]interface{}) (*api.Result, error)
	Assert(*api.ResultSet) bool
}

type defaulCelEvaluator struct{}

// compileTenets compiles the CEL code from the teenets into their syntax trees.
func (dce *defaulCelEvaluator) CompileTenet(env *cel.Env, tenet *api.Tenet) (*cel.Ast, error) {
	// Compile the tenets into their ASTs
	if env == nil {
		return nil, fmt.Errorf("unable to compile tenet, no cel environment created")
	}
	ast, iss := env.Compile(tenet.Code)
	if iss.Err() != nil {
		return nil, fmt.Errorf("compiling tenet %w", iss.Err())
	}

	return ast, nil
}

// CreateEnvironment
func (dce *defaulCelEvaluator) CreateEnvironment() (*cel.Env, error) {
	envOpts := []cel.EnvOption{
		cel.Variable(VarNamePredicates, cel.MapType(cel.IntType, cel.AnyType)),
		ext.Bindings(),
		ext.Strings(),
		ext.Encoders(),
	}

	env, err := cel.NewEnv(
		envOpts...,
	)
	if err != nil {
		return nil, (fmt.Errorf("creating CEL environment: %w", err))
	}

	return env, nil
}

// BuildVariables builds the set of variables that will be exposed in the
// CEL runtime.
func (dce *defaulCelEvaluator) BuildVariables(predicates []attestation.Predicate) (*map[string]any, error) {
	ret := map[string]any{}
	preds := []*structpb.Value{}

	for _, p := range predicates {
		d := map[string]any{}
		if err := json.Unmarshal(p.GetData(), &d); err != nil {
			return nil, fmt.Errorf("unmarshalling predicate data: %w", err)
		}
		val, err := structpb.NewValue(map[string]any{
			"predicate_type": string(p.GetType()),
			"data":           d,
		})
		if err != nil {
			return nil, fmt.Errorf("serializing predicate: %w", err)
		}
		preds = append(preds, val)
	}
	ret[VarNamePredicates] = preds
	return &ret, nil
}

// Evaluate the precompiled ASTs
func (dce *defaulCelEvaluator) Evaluate(env *cel.Env, ast *cel.Ast, variables *map[string]any) (*api.Result, error) {
	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("generating program from AST: %w", err)
	}
	// logrus.Debugf("variables: %+v", variables)
	if variables == nil {
		return nil, fmt.Errorf("variable set undefined")
	}

	// First evaluate the tenet.
	result, deets, err := program.Eval(*variables)
	logrus.Infof("Eval result: %+v deets: %+v", result, deets)
	if err != nil {
		return nil, fmt.Errorf("evaluation error: %w", err)
	}

	st := "FAILED"

	if result.Value().(bool) {
		st = "PASSED"
	}

	// Convert cel result to an api.Result
	return &api.Result{
		Status:     st,
		Date:       timestamppb.New(time.Now()),
		Policy:     &api.PolicyRef{},
		Statements: []*api.StatementRef{},
		Data:       []*api.Output{},
	}, nil
}

func (dce *defaulCelEvaluator) Assert(*api.ResultSet) bool {
	return false
}
