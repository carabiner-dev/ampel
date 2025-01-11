package verifier

import (
	"context"

	v1 "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
)

type AmpelImplementation interface {
}

func New() *Ampel {
	return &Ampel{
		impl: &defaultIplementation{},
	}
}

// Ampel is the attestation verifier
type Ampel struct {
	impl AmpelImplementation
	/// StorageBackends []*storage.Repository
}

type VerificationOptions struct {
	AttestationFiles []string
}

// VerifyObject
func (ampel *Ampel) Verify(ctx context.Context, opts *VerificationOptions, policy *v1.PolicySet, subjects []*attestation.Subject) (*v1.Result, error) {
	// Fetch applicable evidence
	// Transform Evidence
	// Eval Policy
	// Generate outputs
	return nil, nil
}
