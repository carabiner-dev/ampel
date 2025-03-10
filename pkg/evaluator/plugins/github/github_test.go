// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"fmt"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"
)

func TestParseRepo(t *testing.T) {
	t.Parallel()
	u := New()
	env, err := cel.NewEnv(
		u.Library(),
	)
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		url      string
		expected map[string]string
		mustErr  bool
	}{
		{"normal", "https://github.com/carabiner-dev/reponame", map[string]string{"host": "github.com", "org": "carabiner-dev", "repo": "reponame", "scheme": "https"}, false},
		{"no-scheme", "github.com/carabiner-dev/reponame", map[string]string{"host": "github.com", "org": "carabiner-dev", "repo": "reponame", "scheme": "https"}, false},
		{"no-repo", "https://github.com/carabiner-dev/", map[string]string{"host": "github.com", "org": "carabiner-dev", "repo": "", "scheme": "https"}, false},
		{"no-org", "https://github.com/", nil, true},
		{"no-org-no-scheme", "github.com/", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ast, iss := env.Compile(fmt.Sprintf("github.parseRepo(\"%s\")", tc.url))
			require.NoError(t, iss.Err())

			program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
			require.NoError(t, err)

			result, _, err := program.Eval(u.VarValues())
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, result.Value())
		})
	}
}

func TestUriToOrg(t *testing.T) {
	t.Parallel()
	u := New()
	env, err := cel.NewEnv(
		u.Library(),
	)
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		url      string
		expected map[string]any
		mustErr  bool
	}{
		{"normal", "https://github.com/carabiner-dev", map[string]any{"name": "github.com/carabiner-dev", "uri": "https://github.com/carabiner-dev", "digest": map[string]string{"sha256": "2775bba8b2170bef2f91b79d4f179fd87724ffee32b4a20b8304856fd3bf4b8f"}}, false},
		{"no-scheme", "github.com/carabiner-dev", map[string]any{"name": "github.com/carabiner-dev", "uri": "https://github.com/carabiner-dev", "digest": map[string]string{"sha256": "2775bba8b2170bef2f91b79d4f179fd87724ffee32b4a20b8304856fd3bf4b8f"}}, false},
		{"no-org", "github.com", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ast, iss := env.Compile(fmt.Sprintf("github.orgDescriptorFromURI(\"%s\")", tc.url))
			require.NoError(t, iss.Err())

			program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
			require.NoError(t, err)

			result, _, err := program.Eval(u.VarValues())
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, result.Value())
		})
	}
}

func TestUriToRepo(t *testing.T) {
	t.Parallel()
	u := New()
	env, err := cel.NewEnv(
		u.Library(),
	)
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		url      string
		expected map[string]any
		mustErr  bool
	}{
		{"normal", "https://github.com/carabiner-dev/repo", map[string]any{"name": "github.com/carabiner-dev/repo", "uri": "https://github.com/carabiner-dev/repo", "digest": map[string]string{"sha256": "9cca8b6535915fc37253bf382d7fadd963df9e0cdddf78321e4ccde8c88d16d2"}}, false},
		{"no-scheme", "github.com/carabiner-dev/repo", map[string]any{"name": "github.com/carabiner-dev/repo", "uri": "https://github.com/carabiner-dev/repo", "digest": map[string]string{"sha256": "9cca8b6535915fc37253bf382d7fadd963df9e0cdddf78321e4ccde8c88d16d2"}}, false},
		{"no-repo", "github.com/carabiner-dev/", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ast, iss := env.Compile(fmt.Sprintf("github.repoDescriptorFromURI(\"%s\")", tc.url))
			require.NoError(t, iss.Err())

			program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
			require.NoError(t, err)

			result, _, err := program.Eval(u.VarValues())
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, result.Value())
		})
	}
}
