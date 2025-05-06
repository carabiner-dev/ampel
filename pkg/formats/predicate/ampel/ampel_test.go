// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ampel

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/ampel/pkg/attestation"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		filename     string
		mustErr      bool
		expectedType attestation.PredicateType
	}{
		{"policyset", "testdata/test-policyset.json", false, PredicateTypePolicySet},
		{"policy", "testdata/test-policy.json", false, PredicateTypePolicy},
		{"resultset", "testdata/test-results.json", false, PredicateTypeResults},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parser := New()
			data, err := os.ReadFile(tc.filename)
			require.NoError(t, err)
			pred, err := parser.Parse(data)
			require.NoError(t, err)
			require.NotNil(t, pred)
			require.Equal(t, tc.expectedType, pred.GetType())
		})
	}
}

func TestParsePolicySetPredicate(t *testing.T) {
	t.Parallel()
	parser := New()
	data, err := os.ReadFile("testdata/test-policyset.json")
	require.NoError(t, err)
	pred, err := parser.ParsePolicySetPredicate(data)
	require.NoError(t, err)
	require.NotNil(t, pred)
	require.Equal(t, pred.GetType(), PredicateTypePolicySet)
}

func TestParsePolicyPredicate(t *testing.T) {
	t.Parallel()
	parser := New()
	data, err := os.ReadFile("testdata/test-policy.json")
	require.NoError(t, err)
	pred, err := parser.ParsePolicyPredicate(data)
	require.NoError(t, err)
	require.NotNil(t, pred)
	require.Equal(t, pred.GetType(), PredicateTypePolicy)
}

func TestParseResultsPredicate(t *testing.T) {
	t.Parallel()
	parser := New()
	data, err := os.ReadFile("testdata/test-results.json")
	require.NoError(t, err)
	pred, err := parser.ParseResultsPredicate(data)
	require.NoError(t, err)
	require.NotNil(t, pred)
	require.Equal(t, pred.GetType(), PredicateTypeResults)
}
