package verifier

import (
	"context"
	"errors"
	"fmt"

	v1 "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
)

type AmpelImplementation interface {
	GatherAttestations(context.Context, []*attestation.Subject) ([]*attestation.Envelope, error)
	ParseAttestations(context.Context, []string) ([]*attestation.Envelope, error)
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
	atts, err := ampel.impl.GatherAttestations(ctx, subjects)
	if err != nil {
		return nil, fmt.Errorf("gathering evidence: %w", err)
	}

	// Parse any extra files defined in the options
	moreatts, err := ampel.impl.ParseAttestations(ctx, opts.AttestationFiles)
	if err != nil {
		return nil, fmt.Errorf("parsing files: %w", err)
	}
	atts = append(atts, moreatts...)

	// Here, the policy may not require attestations (noop) but
	// it's a stretch, we'll feix it later
	if len(atts) == 0 {
		return nil, errors.New("no evidence found to evaluate policy")
	}

	// Transform Evidence
	// Eval Policy
	// Generate outputs
	return nil, nil
}
