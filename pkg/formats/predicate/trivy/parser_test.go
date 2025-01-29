// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package trivy

import (
	"os"
	"testing"

	"github.com/puerco/ampel/pkg/formats/predicate/generic"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		path        string
		data        []byte
		mustErr     bool
		verifyParse func(*testing.T, *generic.Predicate)
	}{
		{"normal", "testdata/trivy.json", []byte{}, false, func(t *testing.T, pred *generic.Predicate) {
			require.NotNil(t, pred.Parsed)
			parsed, ok := pred.Parsed.(*TrivyReport)
			require.True(t, ok)
			require.Equal(t, "/home/urbano/projects/release", parsed.ArtifactName)
			require.Equal(t, "filesystem", parsed.ArtifactType)
			require.Len(t, parsed.Results, 3)
			require.Len(t, parsed.Results[0].Vulnerabilities, 5)
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
			tpred, ok := pred.(*generic.Predicate)
			require.True(t, ok)
			tc.verifyParse(t, tpred)
		})
	}
}
