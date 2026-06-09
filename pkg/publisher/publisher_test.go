// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package publisher

import (
	"context"
	"testing"

	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// capture is a minimal Publisher used to assert registry/initstring behavior.
type capture struct {
	cfg       *structpb.Struct
	published papi.Results
}

func (c *capture) Init(cfg *structpb.Struct) error { c.cfg = cfg; return nil }

func (c *capture) Publish(_ context.Context, rs papi.Results, _ ...PublishOpt) error {
	c.published = rs
	return nil
}

func TestNew(t *testing.T) {
	t.Parallel()
	last := &capture{}
	Register("test-capture", func() Publisher { last = &capture{}; return last })

	for _, tc := range []struct {
		name      string
		init      string
		mustErr   bool
		assertCfg func(*testing.T, *structpb.Struct)
	}{
		{
			name: "no-spec",
			init: "test-capture:",
			assertCfg: func(t *testing.T, s *structpb.Struct) {
				t.Helper()
				require.Empty(t, s.GetFields())
			},
		},
		{
			name: "bare-spec-under-spec-key",
			init: "test-capture:https://example.com/hook",
			assertCfg: func(t *testing.T, s *structpb.Struct) {
				t.Helper()
				require.Equal(t, "https://example.com/hook", s.GetFields()["spec"].GetStringValue())
			},
		},
		{
			name: "query-spec",
			init: "test-capture:url=https://example.com&timeout=5s",
			assertCfg: func(t *testing.T, s *structpb.Struct) {
				t.Helper()
				require.Equal(t, "https://example.com", s.GetFields()["url"].GetStringValue())
				require.Equal(t, "5s", s.GetFields()["timeout"].GetStringValue())
			},
		},
		{name: "no-scheme", init: "no-colon", mustErr: true},
		{name: "empty-driver", init: ":spec", mustErr: true},
		{name: "unknown-driver", init: "does-not-exist:x", mustErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(tc.init)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, p)
			tc.assertCfg(t, last.cfg)
		})
	}
}

func TestNewSet(t *testing.T) {
	t.Parallel()
	Register("test-set", func() Publisher { return &capture{} })

	pubs, err := NewSet([]string{"test-set:a=1", "test-set:b=2"})
	require.NoError(t, err)
	require.Len(t, pubs, 2)

	_, err = NewSet([]string{"test-set:a=1", "bad-driver:x"})
	require.Error(t, err)
}
