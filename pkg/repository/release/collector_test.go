// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"os"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/require"
)

func TestFetch(t *testing.T) {
	t.Parallel()
	if tok := os.Getenv("GITHUB_TOKEN"); tok == "" {
		t.Log("Skip token, no github token set")
		t.Skip()
	}

	for _, tc := range []struct {
		name        string
		repo        string
		tag         string
		numExpected int
		mustErr     bool
	}{
		{"single-attestation", "protobom/protobom", "v0.5.2", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			collector, err := New(WithRepo(tc.repo), WithTag(tc.tag))
			require.NoError(t, err)
			require.NotNil(t, collector)

			// List the attestations
			all, err := collector.Fetch(t.Context(), attestation.FetchOptions{})
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, all, tc.numExpected)
		})
	}
}
