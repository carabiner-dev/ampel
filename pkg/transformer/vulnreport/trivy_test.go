// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vulnreport

import (
	"os"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/require"

	posv "github.com/carabiner-dev/ampel/pkg/formats/predicate/osv"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/trivy"
)

func TestTrivyToOSV(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		trivyPath     string
		expectedLen   int
		mustErr       bool
		validatePreds func([]attestation.Predicate)
	}{
		{"one-trivy-go", "testdata/trivy.json", 1, false, func(preds []attestation.Predicate) {
			require.Len(t, preds, 1)
			require.Equal(t, preds[0].GetType(), posv.PredicateType)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			xformer := Transformer{}

			// Read the data
			data, err := os.ReadFile(tc.trivyPath)
			require.NoError(t, err)
			pred, err := trivy.New().Parse(data)
			require.NoError(t, err)
			_, ret, err := xformer.Mutate(nil, []attestation.Predicate{
				pred,
			})
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, ret, tc.expectedLen)
			if tc.validatePreds != nil {
				tc.validatePreds(ret)
			}
		})
	}
}
