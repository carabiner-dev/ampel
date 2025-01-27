// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package trivy

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		path        string
		data        []byte
		mustErr     bool
		verifyParse func(*testing.T, *Predicate)
	}{
		{"normal", "testdata/trivy.json", []byte{}, false, func(t *testing.T, pred *Predicate) {
			require.NotNil(t, pred.Parsed)
			require.Equal(t, "/home/urbano/projects/release", pred.Parsed.ArtifactName)
			require.Equal(t, "filesystem", pred.Parsed.ArtifactType)
			require.Len(t, pred.Parsed.Results, 3)
			require.Len(t, pred.Parsed.Results[0].Vulnerabilities, 5)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parser := &Parser{}
			data := tc.data
			var err error
			if len(data) == 0 && tc.path != "" {
				data, err = os.ReadFile(tc.path)
				require.NoError(t, err)
			}
			pred, err := parser.Parse(data)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pred)
			tpred, ok := pred.(*Predicate)
			require.True(t, ok)
			tc.verifyParse(t, tpred)
		})
	}
}
