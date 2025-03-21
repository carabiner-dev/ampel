// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseV02(t *testing.T) {
	t.Parallel()

	// This is just a simple test that ensures the parser can, well, parse
	p := ParserV02{}
	data, err := os.ReadFile("testdata/sample-v0.2.json")
	require.NoError(t, err)
	res, err := p.Parse(data)
	require.NoError(t, err)
	require.NotNil(t, res)

	data, err = os.ReadFile("testdata/bad-v0.2.json")
	require.NoError(t, err)
	_, err = p.Parse(data)
	require.Error(t, err)
}
