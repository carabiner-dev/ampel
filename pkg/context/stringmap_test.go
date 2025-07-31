// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStringMapGetValue(t *testing.T) {
	for _, tt := range []struct {
		name    string
		key     string
		expect  any
		mustErr bool
		sut     []string
	}{
		{
			name: "string-value", expect: "Hello I'm here", key: "test_ks", mustErr: false,
			sut: []string{"test_ks:Hello I'm here"},
		},
		{
			name: "number-value", expect: "1", key: "test_k", mustErr: false,
			sut: []string{"test_k:1"},
		},
		{
			name: "no-colon", expect: nil, key: "test_o", mustErr: false,
			sut: []string{"test_o"},
		},
		{
			name: "no-value", expect: "", key: "test_oo", mustErr: false,
			sut: []string{"test_oo:"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			//	t.Parallel()
			reader := StringMapList(tt.sut)
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
