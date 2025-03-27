// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vulns

import (
	"errors"
	"os"
	"testing"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	v02 "github.com/in-toto/attestation/go/predicates/vulns/v02"
	"github.com/stretchr/testify/require"
)

func TestParseV2(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name              string
		filename          string
		data              []byte
		mustErr           bool
		errType           error
		validatePredicate func(*testing.T, attestation.Predicate)
	}{
		{"v2", "testdata/vulns-v02.json", []byte{}, false, nil, func(t *testing.T, p attestation.Predicate) {
			t.Helper()
			parsed, ok := p.GetParsed().(*v02.Vulns)
			require.True(t, ok)
			require.NotNil(t, parsed.Scanner)
			require.NotNil(t, parsed.Scanner.Db)
			require.NotNil(t, parsed.Scanner.Result)
			require.NotNil(t, parsed.Metadata)
			require.Equal(t, "pkg:github/aquasecurity/trivy@244fd47e07d1004f0aed9", parsed.Scanner.Uri)
			require.Equal(t, "0.19.2", parsed.Scanner.Version)
			require.Equal(t, "pkg:github/aquasecurity/trivy-db/commit/4c76bb580b2736d67751410fa4ab66d2b6b9b27d", parsed.Scanner.Db.Uri)
			require.Len(t, parsed.Scanner.Result, 1)
			require.Equal(t, "CVE-123", parsed.Scanner.Result[0].Id)
			require.Len(t, parsed.Scanner.Result[0].Severity, 2)
		}},
		{"other-json", "", []byte(`{name: "John Doe", "Today": 1, "IsItTrue": false}`), true, attestation.ErrNotCorrectFormat, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := tc.data
			var err error
			if len(data) == 0 && tc.filename != "" {
				data, err = os.ReadFile(tc.filename)
				require.NoError(t, err)
			}
			pred, err := parseV2(data)
			if tc.mustErr {
				if tc.errType != nil {
					require.True(t, errors.Is(err, tc.errType))
				}
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pred)
		})
	}
}
