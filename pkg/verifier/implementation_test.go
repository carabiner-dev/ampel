// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"testing"
	"time"

	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCheckPolicy(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		mustErr bool
		opts    *VerificationOptions
		policy  *papi.Policy
	}{
		{"normal", false, nil, &papi.Policy{Meta: &papi.Meta{Expiration: timestamppb.New(time.Now().Add(1 * time.Hour))}}},
		{"expired", true, nil, &papi.Policy{Meta: &papi.Meta{Expiration: timestamppb.New(time.Now().Add(-1 * time.Hour))}}},
		{"nil-expiration", false, nil, &papi.Policy{Meta: &papi.Meta{Expiration: nil}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			di := &defaultIplementation{}
			err := di.CheckPolicy(t.Context(), tt.opts, tt.policy)
			if tt.mustErr {
				require.Error(t, err)
				require.IsType(t, PolicyError{}, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
