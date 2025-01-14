package evaluator

import (
	"context"
	"fmt"

	api "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/evaluator/cel"
	"github.com/puerco/ampel/pkg/evaluator/options"
)

// Ensure the known evaluators satisfy the interface
var _ Evaluator = (*cel.Evaluator)(nil)

type Factory struct{}

func (f *Factory) Get(c Class) (Evaluator, error) {
	switch c.Name() {
	case "cel":
		return cel.New(), nil
	default:
		return nil, fmt.Errorf("no evaluator defined for class %q", c.Name())
	}
}

// Evaluator
type Evaluator interface {
	ExecTenet(context.Context, options.Options, *api.Tenet, []attestation.Predicate) (*api.Result, error)
}
