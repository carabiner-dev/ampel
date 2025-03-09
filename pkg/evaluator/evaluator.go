// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"context"
	"fmt"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/evaluator/cel"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

// Ensure the known evaluators satisfy the interface
var _ Evaluator = (*cel.Evaluator)(nil)

type Factory struct{}

func (f *Factory) Get(opts *options.EvaluatorOptions, c class.Class) (Evaluator, error) {
	switch c.Name() {
	case "cel":
		return cel.New(opts)
	default:
		return nil, fmt.Errorf("no evaluator defined for class %q", c.Name())
	}
}

// Evaluator
type Evaluator interface {
	ExecTenet(context.Context, *options.EvaluatorOptions, *api.Tenet, []attestation.Predicate) (*api.EvalResult, error)
	ExecChainedSelector(context.Context, *options.EvaluatorOptions, *api.ChainedPredicate, attestation.Predicate) (attestation.Subject, error)
}
