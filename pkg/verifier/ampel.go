package verifier

import (
	v1 "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
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

// VerifyObject
func (ampel *Ampel) Verify(*v1.PolicySet, []*attestation.Subject) (*v1.Result, error) {
	// Fetch applicable evidence
	// Transform Evidence
	// Eval Policy
	// Generate outputs
}

func (ampel *Ampel) VerifySubject(*v1.PolicySet, *attestation.Subject) (*v1.Result, error) {
	// Filter evidence
	// Transform
	// Eval
	// Generate outputs
}
