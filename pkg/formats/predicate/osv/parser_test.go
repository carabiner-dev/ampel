// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"os"
	"testing"

	protoOSV "github.com/carabiner-dev/osv/go/osv"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/ampel/pkg/attestation"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		path        string
		data        []byte
		mustErr     bool
		verifyParse func(*testing.T, attestation.Predicate)
	}{
		{"debian", "testdata/osv-scanner-release.json", []byte{}, false, func(t *testing.T, pred attestation.Predicate) {
			t.Helper()
			require.NotNil(t, pred.GetParsed())
			parsed, ok := pred.GetParsed().(*protoOSV.Results)
			require.True(t, ok)
			require.NotNil(t, parsed.Date)
			require.NotNil(t, parsed.Results)

			require.Len(t, parsed.Results, 1)
			require.Len(t, parsed.Results[0].Packages, 4)
			require.Len(t, parsed.Results[0].Packages[0].Vulnerabilities, 4)
			require.Len(t, parsed.Results[0].Packages[0].Vulnerabilities[0].Affected, 3)

			require.Equal(t, "GHSA-r9px-m959-cxf4", parsed.Results[0].Packages[0].Vulnerabilities[0].Id)
		}},
		{"scanner-2", "testdata/osv-scan-2.0.0.json", []byte{}, false, func(t *testing.T, pred attestation.Predicate) {
			t.Helper()
			require.NotNil(t, pred.GetParsed())
			parsed, ok := pred.GetParsed().(*protoOSV.Results)
			require.True(t, ok)
			require.NotNil(t, parsed.Results)

			require.Len(t, parsed.Results, 1)
			require.Len(t, parsed.Results[0].Packages, 2)
			require.Len(t, parsed.Results[0].Packages[0].Vulnerabilities, 2)
			require.Len(t, parsed.Results[0].Packages[0].Vulnerabilities[0].Affected, 3)

			require.Equal(t, "GHSA-c6gw-w398-hv78", parsed.Results[0].Packages[0].Vulnerabilities[0].Id)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
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
			if tc.verifyParse != nil {
				tc.verifyParse(t, pred)
			}
		})
	}
}
