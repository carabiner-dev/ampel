// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bare

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseStream(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		file    string
		mustErr bool
	}{
		{"normal", "testdata/ampel.spdx.json", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := Parser{}
			f, err := os.Open(tc.file)
			require.NoError(t, err)
			_, err = p.ParseStream(f)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
