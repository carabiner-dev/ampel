package evaluator

import (
	"context"
	"fmt"

	v1 "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/evaluator/options"
)

type Factory struct{}

func Get(c Class) (Evaluator, error) {
	switch c.Name() {
	default:
		return nil, fmt.Errorf("cannot produce evaluator of class %q", c.Name())
	}
}

type Evaluator interface {
	Exec(context.Context, options.Options, *v1.Tenet) (bool, *v1.ResultSet, error)
}
