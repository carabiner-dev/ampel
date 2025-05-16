// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyRefValidate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		mustErr bool
		ref     *PolicyRef
	}{
		{
			"http-requires-hash", true,
			&PolicyRef{
				Location: &ResourceDescriptor{
					Uri: "http://example.com",
				},
			},
		},
		{
			"vcslocator-requires-hash", true,
			&PolicyRef{
				Location: &ResourceDescriptor{
					Uri: "git+http://github.com/example",
				},
			},
		},
		{
			"vcslocator-with-digest", false,
			&PolicyRef{
				Location: &ResourceDescriptor{
					Uri:    "git+http://github.com/example",
					Digest: map[string]string{"sha256": "2347962367823768"},
				},
			},
		},
		{
			"vcslocator-with-commit", false,
			&PolicyRef{
				Location: &ResourceDescriptor{
					Uri: "git+http://github.com/example@59c8563ff26810478b6ab8ff4c779b4e14385392",
				},
			},
		},
		{
			"invalid-hash-algos", true,
			&PolicyRef{
				Location: &ResourceDescriptor{
					Digest: map[string]string{"sha2000-deluxe": "59c8563ff26810478b6ab8ff4c779b4e14385392"},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.ref.Validate()
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
