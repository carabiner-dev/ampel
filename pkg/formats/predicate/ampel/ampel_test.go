// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ampel

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	parser := New()
	data, err := os.ReadFile("testdata/test-policy.json")
	require.NoError(t, err)
	pred, err := parser.Parse(data)
	require.NoError(t, err)
	require.NotNil(t, pred)
	require.Equal(t, pred.GetType(), PredicateTypePolicySet)
}
