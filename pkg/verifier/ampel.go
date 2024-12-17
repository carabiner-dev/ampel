package verifier

import (
	"fmt"

	"github.com/puerco/ampel/pkg/policy"
	"github.com/puerco/ampel/pkg/principal"
	"github.com/puerco/ampel/pkg/storage"
)

type AmpelImplementation interface {
	GetObjectPolicies(*principal.Object) (*policy.Checklist, error)
	EvalObject(*policy.Checklist, *principal.Object) (*policy.ResultSet, error)
}

func New() *Ampel {
	return &Ampel{
		impl: &defaultIplementation{},
	}
}

// Ampel is the attestation verifier
type Ampel struct {
	impl            AmpelImplementation
	StorageBackends []*storage.Repository
}

// CheckObject checks the status of an object
func (ampel *Ampel) CheckObject(obj *principal.Object) (*policy.ResultSet, error) {
	policies, err := ampel.impl.GetObjectPolicies(obj)
	if err != nil {
		return nil, fmt.Errorf("fetching object policies: %w", err)
	}

	res, err := ampel.impl.EvalObject(policies, obj)
	if err != nil {
		return nil, fmt.Errorf("evaluating object: %w", err)
	}
	return res, err
}

// Eval applies a policy
func (ampel *Ampel) Eval(checklist *policy.Checklist, obj *principal.Object) (*policy.ResultSet, error) {
	results := policy.ResultSet{}
	for i, chk := range checklist.Checks {
		res, err := evaluateCheck(chk, obj)
		if err != nil {
			return nil, fmt.Errorf("eval check #%d [%s]", i, chk.ID())
		}
		results.Results = append(results.Results, &res)
	}

	return &results, nil
}

func evaluateCheck(chk policy.Check, obj *principal.Object) (policy.Result, error) {
	res, err := chk.Eval(obj)
	if err != nil {
		return res, fmt.Errorf("eval: %w", err)
	}
	return res, nil
}
