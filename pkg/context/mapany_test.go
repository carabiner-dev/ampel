// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMapAnyGetValue(t *testing.T) {
	for _, tt := range []struct {
		name    string
		key     string
		expect  any
		mustErr bool
		sut     map[string]any
	}{
		{
			name: "normal-value", expect: "hai", key: "test_func1", mustErr: false,
			sut: map[string]any{"test_func1": "hai"},
		},
		{
			name: "not-set", expect: nil, key: "other_key", mustErr: false,
			sut: map[string]any{"test_func1": "hai"},
		},
		{
			name: "nil-map", expect: nil, key: "other_key", mustErr: false,
			sut: nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			//	t.Parallel()
			reader := MapAnyProvider(tt.sut)
			res, err := reader.GetContextValue(tt.key)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expect, res)
		})
	}
}
