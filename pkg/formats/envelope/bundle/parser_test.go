package bundle

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/ampel/pkg/attestation"
)

func TestParseStream(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name             string
		path             string
		mustErr          bool
		validateEnvelope func(*testing.T, []attestation.Envelope)
	}{
		{"slsa", "testdata/bundle-provenance.json", false, func(t *testing.T, at []attestation.Envelope) {
			t.Helper()
			env, ok := at[0].(*Envelope)
			require.True(t, ok, "casting envelope failed")
			require.Equal(t, "application/vnd.dev.sigstore.bundle+json;version=0.1", env.MediaType)
			require.Equal(t, attestation.PredicateType("https://slsa.dev/provenance/v0.2"), at[0].GetStatement().GetPredicateType())
			require.Equal(t, attestation.PredicateType("https://slsa.dev/provenance/v0.2"), at[0].GetStatement().GetPredicate().GetType())
			require.NotNil(t, env.GetStatement())
			require.Equal(t, attestation.PredicateType("https://slsa.dev/provenance/v0.2"), env.GetStatement().GetPredicateType())
		}},
		{"npm", "testdata/bundle-publish.json", false, func(t *testing.T, at []attestation.Envelope) {
			t.Helper()
			env, ok := at[0].(*Envelope)
			require.True(t, ok, "casting envelope failed")
			require.Equal(t, "application/vnd.dev.sigstore.bundle+json;version=0.1", env.MediaType)
			require.NotNil(t, at[0].GetStatement())
			require.Equal(t, attestation.PredicateType("https://github.com/npm/attestation/tree/main/specs/publish/v0.1"), env.GetStatement().GetPredicateType())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parser := Parser{}
			env, err := parser.ParseFile(tc.path)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, env)
			if tc.validateEnvelope != nil {
				tc.validateEnvelope(t, env)
			}
		})
	}
}
