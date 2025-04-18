// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/filters"
)

func TestFetch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		exts        []string
		expect      int
		ignoreOther bool
		mustErr     bool
	}{
		{"all-default", nil, 2, true, false},
		{"ext-spdx", []string{"spdx"}, 1, true, false},
		{"ext-spdx-no-ignore", []string{"spdx"}, 2, false, false},
		{"subpath", nil, 1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			collector, err := New(WithFS(os.DirFS("testdata")))
			// This is hardcoded but we only have on subpath test
			if tc.name == "subpath" {
				collector, err = New(
					WithFS(os.DirFS("testdata")),
					WithPath("subdir"),
				)
			}
			require.NoError(t, err)
			collector.IgnoreOtherFiles = tc.ignoreOther
			if tc.exts != nil {
				collector.Extensions = tc.exts
			}
			atts, err := collector.Fetch(t.Context(), attestation.FetchOptions{})
			require.NoError(t, err)
			require.Len(t, atts, tc.expect)
		})
	}
}

func TestFetchFetchByPredicateType(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		expect  int
		pt      string
		opts    attestation.FetchOptions
		mustErr bool
	}{
		{"pt-ok", 1, "https://spdx.dev/Document", attestation.FetchOptions{}, false},
		{"pt-bad", 0, "something-else", attestation.FetchOptions{}, false},
		{"pt-ok-with-synth-always", 1, "https://spdx.dev/Document", attestation.FetchOptions{
			Query: &attestation.Query{
				Filters: []attestation.Filter{&filters.AlwaysMatch{}},
			},
		}, false},
		{"pt-ok-with-synth-never", 0, "https://spdx.dev/Document", attestation.FetchOptions{
			Query: &attestation.Query{
				Filters: []attestation.Filter{&filters.NeverMatch{}},
			},
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			collector, err := New(WithFS(os.DirFS("testdata")))
			require.NoError(t, err)

			atts, err := collector.FetchByPredicateType(
				t.Context(), tc.opts, []attestation.PredicateType{attestation.PredicateType(tc.pt)},
			)
			require.NoError(t, err)
			require.Len(t, atts, tc.expect)
		})
	}
}
