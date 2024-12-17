package policy

import (
	"github.com/puerco/ampel/pkg/principal"
)

type Result struct {
	Error error
}

type ResultSet struct {
	Results []*Result
}

type Check interface {
	// ID is the Check identifier. A short, string with no spaces.
	ID() string

	// Eval evaluates the policy against the specified subjects
	Eval(*principal.Object) (Result, error)
}

type Checklist struct {
	Checks []Check
}
