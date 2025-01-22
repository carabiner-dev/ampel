package vulns

import (
	"errors"
	"os"
	"testing"

	"github.com/puerco/ampel/pkg/attestation"
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
		validatePredicate func(*testing.T, *PredicateV2)
	}{
		{"v2", "testdata/vulns-v02.json", []byte{}, false, nil, func(t *testing.T, p *PredicateV2) {
			t.Helper()
			require.NotNil(t, p.Parsed)
			require.NotNil(t, p.Parsed.Scanner)
			require.NotNil(t, p.Parsed.Scanner.Database)
			require.NotNil(t, p.Parsed.Scanner.Result)
			require.NotNil(t, p.Parsed.ScanMetadata)
			require.Equal(t, p.Parsed.Scanner.Uri, "pkg:github/aquasecurity/trivy@244fd47e07d1004f0aed9")
			require.Equal(t, p.Parsed.Scanner.Version, "0.19.2")
			require.Equal(t, p.Parsed.Scanner.Database.Uri, "pkg:github/aquasecurity/trivy-db/commit/4c76bb580b2736d67751410fa4ab66d2b6b9b27d")
			require.Len(t, p.Parsed.Scanner.Result, 1)
			require.Equal(t, p.Parsed.Scanner.Result[0].Id, "CVE-123")
			require.Len(t, p.Parsed.Scanner.Result[0].Severity, 2)
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

			// These are hardcoded for now

		})
	}
}
