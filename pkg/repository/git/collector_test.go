// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"path/filepath"
	"testing"

	"sigs.k8s.io/release-utils/tar"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestClone(t *testing.T) {
	t.Parallel()

	// unpack test repository to tmp
	dir := t.TempDir()
	require.NoError(t, tar.Extract("testdata/repo.tar.gz", dir))
	logrus.Info(filepath.Join(dir, "repo"))
	for _, tc := range []struct {
		name        string
		init        string
		expectedNum int
		mustErr     bool
	}{
		{"root", filepath.Join(dir, "repo"), 3, false},
		{"subpath", filepath.Join(dir, "repo") + "#sboms", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(WithLocator(tc.init))
			require.NoError(t, err)

			err = c.clone()
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Check if the methods work
			res, err := c.Fetch(t.Context(), attestation.FetchOptions{})
			require.NoError(t, err, err)
			require.Len(t, res, tc.expectedNum)
		})
	}
}
