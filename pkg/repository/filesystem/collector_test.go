// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"context"
	"os"
	"testing"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/stretchr/testify/require"
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
		{"all-default", []string{"spdx"}, 1, true, false},
		{"all-default", []string{"spdx"}, 2, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			collector := New(os.DirFS("testdata"))
			collector.IgnoreOtherFiles = tc.ignoreOther
			if tc.exts != nil {
				collector.Extensions = tc.exts
			}
			atts, err := collector.Fetch(context.Background(), attestation.FetchOptions{})
			require.NoError(t, err)
			require.Len(t, atts, tc.expect)
		})
	}
}
