// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"testing"

	gointoto "github.com/in-toto/attestation/go/v1"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"
)

// TestChainReachesTenets proves a policy's tenets see the chain the policy
// followed: the hop's type, source, destination and the predicate it was
// read from, so the tenet can compare what it finds at the end of the chain
// with what the chain was read from.
func TestChainReachesTenets(t *testing.T) {
	t.Parallel()
	opts := whenTestOptions()
	opts.AttestationFiles = []string{"testdata/wtf-frontend.spdx.json", "testdata/link1.json"}
	opts.AdmitUnverified = true
	subject := &gointoto.ResourceDescriptor{
		Name:   "test",
		Digest: map[string]string{"sha256": "851074691728c479a4c83628de8310eaca792cc7"},
	}
	link := &papi.ChainLink{Source: &papi.ChainLink_Predicate{Predicate: &papi.ChainedPredicate{
		Type:     "https://spdx.dev/Document",
		Selector: "'sha1:856314ba21181a746186c24f1647d06e45048964'",
	}}}
	for _, tc := range []struct {
		name   string
		code   string
		status string
	}{
		{"sees-the-hop", `size(chain) == 1 && chain[0].type == "https://spdx.dev/Document"`, papi.StatusPASS},
		{"sees-the-ends", `chain[0].source.digest.sha256 == "851074691728c479a4c83628de8310eaca792cc7" && chain[0].destination.digest.sha1 == "856314ba21181a746186c24f1647d06e45048964"`, papi.StatusPASS},
		{"reads-the-hop-predicate", `chain[0].predicate.data.spdxVersion == "SPDX-2.3" && chain[0].predicate.predicate_type == "https://spdx.dev/Document"`, papi.StatusPASS},
		{"compares-across-the-hop", `chain[0].predicate.data.spdxVersion == "SPDX-9.9"`, papi.StatusFAIL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			policy := &papi.Policy{
				Id:         tc.name,
				Meta:       &papi.Meta{},
				Chain:      []*papi.ChainLink{link},
				Predicates: &papi.PredicateSpec{Types: []string{"https://example.com/"}},
				Tenets:     []*papi.Tenet{{Id: "t1", Code: tc.code}},
			}
			ampel, err := New()
			require.NoError(t, err)
			res, err := ampel.VerifySubjectWithPolicy(context.Background(), opts, policy, subject)
			require.NoError(t, err)
			require.Equal(t, tc.status, res.GetStatus(), res.GetEvalResults())
			require.Len(t, res.GetChain(), 1, "the result records the hop")
		})
	}

	// The condition sees the chain as well.
	policy := &papi.Policy{
		Id:         "when-sees-chain",
		Meta:       &papi.Meta{},
		Chain:      []*papi.ChainLink{link},
		Predicates: &papi.PredicateSpec{Types: []string{"https://example.com/"}},
		When:       &papi.When{Expression: `chain[0].predicate.data.spdxVersion == "SPDX-9.9"`},
		Tenets:     []*papi.Tenet{{Id: "t1", Code: "true"}},
	}
	ampel, err := New()
	require.NoError(t, err)
	res, err := ampel.VerifySubjectWithPolicy(context.Background(), opts, policy, subject)
	require.NoError(t, err)
	require.Equal(t, papi.StatusSKIP, res.GetStatus())
}
