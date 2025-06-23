// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package note

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractCommitBundle(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		locator string
		notNil  bool
		mustErr bool
	}{
		{
			name:    "sharded",
			locator: "slsa-framework/slsa-source-poc@28a0276dde459992f3d8bbb4cb41cd34313a99ff",
			notNil:  true,
			mustErr: false,
		},
		{
			name:    "files",
			locator: "puerco/lab@fc3b05868b9d0378c7333122d1f1f80b51b08416",
			notNil:  true,
			mustErr: false,
		},
		{
			name:    "nodata",
			locator: "puerco/lab@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			notNil:  false,
			mustErr: false,
		},
		{
			name:    "error",
			locator: "puerco/lab-other-repo-that-does-not-exist@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Collector{
				Options: Options{Locator: tc.locator},
			}
			reader, err := c.extractCommitBundle()
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			data, err := io.ReadAll(reader)
			require.NoError(t, err)
			if tc.notNil {
				require.NotEmpty(t, data)
			} else {
				require.Empty(t, data)
			}
		})
	}
}
