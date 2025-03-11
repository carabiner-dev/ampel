// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cel

import (
	"context"
	"fmt"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
	"github.com/carabiner-dev/ampel/pkg/evaluator/plugins/github"
	"github.com/carabiner-dev/ampel/pkg/evaluator/plugins/hasher"
	"github.com/carabiner-dev/ampel/pkg/evaluator/plugins/url"
	"github.com/google/cel-go/cel"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/structpb"
)

var Class = class.Class("cel@v0")

const (
	VarNamePredicate  = "predicate"
	VarNamePredicates = "predicates"
	VarNameContext    = "context"
	VarNameOutputs    = "outputs"
)

// New creates a new CEL evaluator with the default options
func New(funcs ...options.OptFunc) (*Evaluator, error) {
	opts := options.Default
	for _, fn := range funcs {
		if err := fn(&opts); err != nil {
			return nil, err
		}
	}

	return NewWithOptions(&opts)
}

func NewWithOptions(opts *options.EvaluatorOptions) (*Evaluator, error) {
	eval := &Evaluator{
		Plugins: map[string]Plugin{},
		impl:    &defaulCelEvaluator{},
	}
	if err := eval.rebuildEnvironment(opts); err != nil {
		return nil, err
	}
	return eval, nil
}

// rebuildEnvironment builds the environment with the current settings
func (e *Evaluator) rebuildEnvironment(opts *options.EvaluatorOptions) error {
	if opts.LoadDefaultPlugins {
		if err := e.RegisterPlugin(hasher.New()); err != nil {
			return fmt.Errorf("registering hasher: %w", err)
		}
		if err := e.RegisterPlugin(url.New()); err != nil {
			return fmt.Errorf("registering url: %w", err)
		}
		if err := e.RegisterPlugin(github.New()); err != nil {
			return fmt.Errorf("registering github: %w", err)
		}
	}

	// Create the env
	env, err := e.impl.CreateEnvironment(opts, e.Plugins)
	if err != nil {
		return fmt.Errorf("creating environment: %w", err)
	}
	e.Environment = env
	return nil
}

// Evaluator implements the evaluator.Evaluator interface to evaluate CEL code
type Evaluator struct {
	Environment *cel.Env
	Plugins     map[string]Plugin
	impl        CelEvaluatorImplementation
}

type Plugin interface {
	// CanRegisterDataFor implements the plugin api function that flags if
	// the plugin is compatible with a class of evaluator
	CanRegisterFor(class.Class) bool

	// EnvVariables returns the data (as a cel.Variable list) that will be
	// registered as global variables in the evaluation environment
	Library() cel.EnvOption

	// VarValues returns the values of the variables handled by the plugin
	VarValues() map[string]any
}

// RegisterPlugin registers a plugin expanding the CEL API available at eval time
func (e *Evaluator) RegisterPlugin(plugin api.Plugin) error {
	// Register the plugin in the data collection
	if api.PluginHasCapability(api.CapabilityEvalEnginePlugin, plugin) {
		if p, ok := plugin.(api.EvalEnginePlugin); ok {
			if !p.CanRegisterFor(Class) {
				return nil
			}
		} else {
			return fmt.Errorf("unable to cast plugin to api.EvalEngineDataPlugin")
		}

		dp, ok := plugin.(Plugin)
		if !ok {
			return fmt.Errorf("plugin declares compatibility with %s but does not implement cel.Plugin", Class)
		}
		e.Plugins[fmt.Sprintf("%T", dp)] = dp
	}

	return nil
}

func (e *Evaluator) ExecChainedSelector(
	ctx context.Context, opts *options.EvaluatorOptions, chained *api.ChainedPredicate, predicate attestation.Predicate,
) (attestation.Subject, error) {
	vars, err := e.impl.BuildSelectorVariables(opts, e.Plugins, chained, predicate)
	if err != nil {
		return nil, fmt.Errorf("building selector variable set: %w", err)
	}

	ast, err := e.impl.CompileCode(e.Environment, chained.Selector)
	if err != nil {
		return nil, fmt.Errorf("compiling selector program: %w", err)
	}

	subject, err := e.impl.EvaluateChainedSelector(e.Environment, ast, vars)
	if err != nil {
		return nil, fmt.Errorf("evaluating chained subject: %w", err)
	}
	logrus.Infof("chained subject: %+v", subject)
	return subject, nil
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

	vars, err := e.impl.BuildVariables(opts, e.Plugins, tenet, predicates)
	if err != nil {
		return nil, fmt.Errorf("building variables for eval environment: %w", err)
	}

	// If the tenet requires predicates, ensure the variables array has them
	status, err := e.impl.EnsurePredicates(tenet, vars)
	if err != nil {
		return nil, fmt.Errorf("ensuring predicates are loaded: %w", err)
	}
	if status != nil {
		return status, nil
	}

	outputMap, err := e.impl.EvaluateOutputs(e.Environment, outputAsts, vars)
	if err != nil {
		return nil, fmt.Errorf("evaluating outputs: %w", err)
	}

	// Add the outputs to the variables
	(*vars)["outputs"] = outputMap

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
