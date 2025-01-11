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

func Get(c Class) (Evaluator, error) {
	switch c.Name() {
	case "cel":
		return &cel.Evaluator{}, nil
	default:
		return nil, fmt.Errorf("cannot produce evaluator of class %q", c.Name())
	}
}

// Evaluator
type Evaluator interface {
	Exec(context.Context, options.Options, []*api.Tenet, []*attestation.Statement) (*api.ResultSet, error)
}
