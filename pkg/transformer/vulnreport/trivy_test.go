// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vulnreport

import (
	"os"
	"testing"

	"github.com/carabiner-dev/attestation"
	posv "github.com/carabiner-dev/collector/predicate/osv"
	"github.com/carabiner-dev/collector/predicate/trivy"
	"github.com/carabiner-dev/collector/predicate/vulns"
	v02 "github.com/in-toto/attestation/go/predicates/vulns/v02"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestMutate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		trivyPath     string
		config        *structpb.Struct
		expectedLen   int
		mustErr       bool
		validatePreds func(*testing.T, []attestation.Predicate)
	}{
		{
			name:        "default-output-is-osv",
			trivyPath:   "testdata/trivy.json",
			config:      nil,
			expectedLen: 1,
			validatePreds: func(t *testing.T, preds []attestation.Predicate) {
				t.Helper()
				require.Equal(t, posv.PredicateType, preds[0].GetType())
			},
		},
		{
			name:      "explicit-osv-output",
			trivyPath: "testdata/trivy.json",
			config: mustStruct(t, map[string]any{
				"output": OutputOSV,
			}),
			expectedLen: 1,
			validatePreds: func(t *testing.T, preds []attestation.Predicate) {
				t.Helper()
				require.Equal(t, posv.PredicateType, preds[0].GetType())
			},
		},
		{
			name:      "vulnreport-output",
			trivyPath: "testdata/trivy.json",
			config: mustStruct(t, map[string]any{
				"output": OutputVulnReport,
			}),
			expectedLen: 1,
			validatePreds: func(t *testing.T, preds []attestation.Predicate) {
				t.Helper()
				require.Equal(t, vulns.PredicateType, preds[0].GetType())
				report, ok := preds[0].GetParsed().(*v02.Vulns)
				require.True(t, ok, "parsed predicate must be *v02.Vulns")
				require.Equal(t, trivyScannerURI, report.GetScanner().GetUri())
				require.NotNil(t, report.GetMetadata().GetScanStartedOn())
				require.NotEmpty(t, report.GetScanner().GetResult(), "must emit at least one result")
				first := report.GetScanner().GetResult()[0]
				require.NotEmpty(t, first.GetId())
				require.NotEmpty(t, first.GetAnnotations(), "results must carry package annotations")
				require.NotEmpty(t, preds[0].GetData(), "predicate data must be marshaled")
			},
		},
		{
			name:      "unknown-output-rejected",
			trivyPath: "testdata/trivy.json",
			config: mustStruct(t, map[string]any{
				"output": "totally-bogus",
			}),
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			xformer := New()
			err := xformer.Init(tc.config)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			data, err := os.ReadFile(tc.trivyPath)
			require.NoError(t, err)
			pred, err := trivy.New().Parse(data)
			require.NoError(t, err)
			_, ret, err := xformer.Mutate(nil, []attestation.Predicate{pred})
			require.NoError(t, err)
			require.Len(t, ret, tc.expectedLen)
			if tc.validatePreds != nil {
				tc.validatePreds(t, ret)
			}
		})
	}
}

func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	require.NoError(t, err)
	return s
}
