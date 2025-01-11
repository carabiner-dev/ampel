package verifier

import (
	"context"

	api "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
)

type defaultIplementation struct{}

func (di *defaultIplementation) GatherAttestations(context.Context, []*attestation.Subject) ([]*attestation.Envelope, error)
func (di *defaultIplementation) ParseAttestations(context.Context, []string) ([]*attestation.Envelope, error)

// AssertResults conducts the final assertion to allow/block based on the
// result sets returned by the evaluators.
func (di *defaultIplementation) AssertResults([]*api.ResultSet) (bool, error) {
	return true, nil
}
