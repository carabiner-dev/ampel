package verifier

import (
	"context"

	"github.com/puerco/ampel/pkg/attestation"
)

type defaultIplementation struct{}

func (di *defaultIplementation) GatherAttestations(context.Context, []*attestation.Subject) ([]*attestation.Envelope, error)
func (di *defaultIplementation) ParseAttestations(context.Context, []string) ([]*attestation.Envelope, error)
