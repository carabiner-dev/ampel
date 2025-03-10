// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cel

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CelEvaluatorImplementation interface {
	CompileCode(*cel.Env, string) (*cel.Ast, error)
	CreateEnvironment(*options.EvaluatorOptions, map[string]Plugin) (*cel.Env, error)
	BuildVariables(*options.EvaluatorOptions, map[string]Plugin, *api.Tenet, []attestation.Predicate) (*map[string]interface{}, error)
	EvaluateOutputs(*cel.Env, map[string]*cel.Ast, *map[string]any) (map[string]any, error)
	Evaluate(*cel.Env, *cel.Ast, *map[string]any) (*api.EvalResult, error)
	Assert(*api.ResultSet) bool
	BuildSelectorVariables(*options.EvaluatorOptions, map[string]Plugin, *api.ChainedPredicate, attestation.Predicate) (*map[string]interface{}, error)
	EvaluateChainedSelector(*cel.Env, *cel.Ast, *map[string]any) (attestation.Subject, error)
}

type defaulCelEvaluator struct{}

// compileCode compiles CEL code from the tenets or output into their syntax trees.
func (dce *defaulCelEvaluator) CompileCode(env *cel.Env, code string) (*cel.Ast, error) {
	// Compile the tenets into their ASTs
	if env == nil {
		return nil, fmt.Errorf("unable to compile CEL code, environment is nil")
	}
	ast, iss := env.Compile(code)
	if iss.Err() != nil {
		return nil, fmt.Errorf("compiling CEL code %w", iss.Err())
	}

	return ast, nil
}

// CreateEnvironment
func (dce *defaulCelEvaluator) CreateEnvironment(_ *options.EvaluatorOptions, plugins map[string]Plugin) (*cel.Env, error) {
	envOpts := []cel.EnvOption{
		cel.Variable(VarNamePredicates, cel.MapType(cel.IntType, cel.AnyType)),
		cel.Variable(VarNamePredicate, cel.AnyType),
		cel.Variable(VarNameContext, cel.AnyType),
		cel.Variable(VarNameOutputs, cel.AnyType),
		ext.Bindings(),
		ext.Strings(),
		ext.Encoders(),
	}

	for _, plugin := range plugins {
		envOpts = append(envOpts, plugin.Library())
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
func (dce *defaulCelEvaluator) BuildVariables(opts *options.EvaluatorOptions, plugins map[string]Plugin, tenet *api.Tenet, predicates []attestation.Predicate) (*map[string]any, error) {
	ret := map[string]any{}

	// Collected predicates
	preds := []*structpb.Value{}
	for _, p := range predicates {
		if tenet.Predicates != nil {
			if len(tenet.Predicates.Types) > 0 && !slices.Contains(tenet.Predicates.Types, string(p.GetType())) {
				logrus.Debugf("skipping predicate of type %q (not in tenet predicate types)", p.GetType())
				continue
			}
		}
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

	// Context
	var contextData = map[string]any{}
	if opts.Context != nil {
		contextData = opts.Context.ToMap()
	}
	s, err := structpb.NewStruct(contextData)
	if err != nil {
		return nil, fmt.Errorf("structuring context data: %w", err)
	}
	ret[VarNameContext] = s

	logrus.Infof("%d CEL plugins loaded into the eval engine. Querying for variables", len(plugins))
	for _, p := range plugins {
		for name, val := range p.VarValues() {
			logrus.Infof("Registered variable: %s: %+v", name, val)
			ret[name] = val
		}
	}
	return &ret, nil
}

// EvaluateOutputs
func (dce *defaulCelEvaluator) EvaluateOutputs(
	env *cel.Env, outputAsts map[string]*cel.Ast, vars *map[string]any,
) (map[string]any, error) {
	var evalResult = map[string]any{}
	if env == nil {
		return nil, fmt.Errorf("CEL environment not set")
	}
	if vars == nil {
		return nil, fmt.Errorf("variable set undefined")
	}
	for id, ast := range outputAsts {
		program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		if err != nil {
			return nil, fmt.Errorf("generating program from AST: %w", err)
		}

		// First evaluate the tenet.
		result, _, err := program.Eval(*vars)
		if err != nil {
			return nil, fmt.Errorf("evaluation error: %w", err)
		}

		evalResult[id] = result.Value()
	}

	// Round tripit
	data, err := json.Marshal(evalResult)
	if err != nil {
		return nil, fmt.Errorf("marshaling output evals: %w", err)
	}

	// Unmarshal to generic
	ret := map[string]any{}
	if err := json.Unmarshal(data, &ret); err != nil {
		return nil, fmt.Errorf("unmarshaling data: %w", err)
	}

	// spew.Dump(ret)

	(*vars)["outputs"] = ret
	return ret, nil
}

// EvaluateChainedSelector
func (dce *defaulCelEvaluator) EvaluateChainedSelector(
	env *cel.Env, ast *cel.Ast, vars *map[string]any,
) (attestation.Subject, error) {
	if env == nil {
		return nil, fmt.Errorf("CEL environment not set")
	}
	if vars == nil {
		return nil, fmt.Errorf("variable set undefined")
	}

	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("generating program from AST: %w", err)
	}

	// First evaluate the tenet.
	result, _, err := program.Eval(*vars)
	if err != nil {
		return nil, fmt.Errorf("evaluation error: %w", err)
	}

	switch v := result.Value().(type) {
	case string:
		algo, val, ok := strings.Cut(v, ":")
		if !ok {
			return nil, fmt.Errorf("string returned not formatted as algorithm:value")
		}
		if _, ok := intoto.HashAlgorithms[strings.ToLower(algo)]; !ok {
			return nil, fmt.Errorf("invalid hash algorithm returned from selector (%q)", v)
		}
		return &intoto.ResourceDescriptor{
			Digest: map[string]string{
				strings.ToLower(algo): val,
			},
		}, nil
	case map[ref.Val]ref.Val, *structpb.Struct:
		res, err := result.ConvertToNative(reflect.TypeOf(&intoto.ResourceDescriptor{}))
		if err != nil {
			return nil, fmt.Errorf("converting eval result to Subject: %w", err)
		}
		subj, ok := res.(*intoto.ResourceDescriptor)
		if !ok {
			return nil, errors.New("selectror must return a string or cel.Subject struct")
		}
		return subj, nil
	default:
		return nil, fmt.Errorf("predicate selector must return string or resource descr (got %T)", result.Value())
	}
}

// Evaluate the precompiled ASTs
func (dce *defaulCelEvaluator) Evaluate(env *cel.Env, ast *cel.Ast, variables *map[string]any) (*api.EvalResult, error) {
	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("generating program from AST: %w", err)
	}
	// logrus.Debugf("variables: %+v", variables)
	if variables == nil {
		return nil, fmt.Errorf("variable set undefined")
	}

	// First evaluate the tenet.
	result, _, err := program.Eval(*variables)
	if err != nil {
		return nil, fmt.Errorf("evaluation error: %w", err)
	}

	// Tenets must evaluate to true always
	evalResult, ok := result.Value().(bool)
	if !ok {
		return nil, fmt.Errorf("eval error: tenet must evaluate to boolean")
	}

	st := api.StatusFAIL
	if evalResult {
		st = api.StatusPASS
	}

	// Convert cel result to an api.Result
	return &api.EvalResult{
		Status: st,
		Date:   timestamppb.New(time.Now()),
		// Policy:     &api.PolicyRef{},
		Statements: []*api.StatementRef{},
	}, nil
}

func (dce *defaulCelEvaluator) Assert(*api.ResultSet) bool {
	return false
}

// BuildSelectorVariables
func (dce *defaulCelEvaluator) BuildSelectorVariables(
	opts *options.EvaluatorOptions, plugins map[string]Plugin, _ *api.ChainedPredicate, predicate attestation.Predicate,
) (*map[string]interface{}, error) {
	ret := map[string]any{}

	// Collected predicates
	preds := []*structpb.Value{}
	d := map[string]any{}
	if err := json.Unmarshal(predicate.GetData(), &d); err != nil {
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}
	val, err := structpb.NewValue(map[string]any{
		"predicate_type": string(predicate.GetType()),
		"data":           d,
	})
	if err != nil {
		return nil, fmt.Errorf("serializing predicate: %w", err)
	}
	preds = append(preds, val)

	ret[VarNamePredicates] = preds
	ret[VarNamePredicate] = val

	// Add the context to the runtime environment
	var contextData = map[string]any{}
	if opts.Context != nil {
		contextData = opts.Context.ToMap()
	}

	s, err := structpb.NewStruct(contextData)
	if err != nil {
		return nil, fmt.Errorf("structuring context data: %w", err)
	}
	ret[VarNameContext] = s

	logrus.Infof("%d CEL plugins loaded into the eval engine. Querying for variables", len(plugins))
	for _, p := range plugins {
		maps.Copy(ret, p.VarValues())
	}

	return &ret, nil
}
