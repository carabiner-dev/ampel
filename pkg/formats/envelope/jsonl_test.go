// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJsonl(t *testing.T) {
	parser := NewJSONL()

	// Ingest the onebad test file which has 7 lines, one bad which
	// should not be read.
	atts, err := parser.ParseFile("testdata/onebad.jsonl")
	require.NoError(t, err)

	require.Len(t, atts, 6)
}
