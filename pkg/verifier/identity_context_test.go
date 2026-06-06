// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"testing"

	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/stretchr/testify/require"
)

func exactM(s string) *sapi.StringMatcher {
	return &sapi.StringMatcher{Kind: &sapi.StringMatcher_Exact{Exact: s}}
}
func regexM(s string) *sapi.StringMatcher {
	return &sapi.StringMatcher{Kind: &sapi.StringMatcher_Regex{Regex: s}}
}
func prefixM(s string) *sapi.StringMatcher {
	return &sapi.StringMatcher{Kind: &sapi.StringMatcher_Prefix{Prefix: s}}
}
func globM(s string) *sapi.StringMatcher {
	return &sapi.StringMatcher{Kind: &sapi.StringMatcher_Glob{Glob: s}}
}

// matcherValue returns the matcher's set string regardless of kind.
func matcherValue(m *sapi.StringMatcher) string {
	switch k := m.GetKind().(type) {
	case *sapi.StringMatcher_Exact:
		return k.Exact
	case *sapi.StringMatcher_Regex:
		return k.Regex
	case *sapi.StringMatcher_Prefix:
		return k.Prefix
	case *sapi.StringMatcher_Glob:
		return k.Glob
	}
	return ""
}

// TestResolvePolicyIdentitiesKinds: every StringMatcher kind renders its template.
func TestResolvePolicyIdentitiesKinds(t *testing.T) {
	t.Parallel()
	ctx := map[string]any{"x": "filled"}
	for _, tt := range []struct {
		name string
		in   *sapi.StringMatcher
		want string
	}{
		{"exact", exactM("a/{{ .Context.x }}"), "a/filled"},
		{"regex", regexM("^{{ .Context.x }}$"), "^filled$"},
		{"prefix", prefixM("{{ .Context.x }}/"), "filled/"},
		{"glob", globM("{{ .Context.x }}/*"), "filled/*"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			id := &sapi.Identity{Sigstore: &sapi.IdentitySigstore{IssuerMatch: tt.in}}
			out, err := resolvePolicyIdentities([]*sapi.Identity{id}, ctx)
			require.NoError(t, err)
			require.Equal(t, tt.want, matcherValue(out[0].GetSigstore().GetIssuerMatch()))
		})
	}
}

// TestResolvePolicyIdentitiesFields: all matcher fields on one identity render,
// including the outer matchers slice and a key matcher.
func TestResolvePolicyIdentitiesFields(t *testing.T) {
	t.Parallel()
	id := &sapi.Identity{
		Sigstore: &sapi.IdentitySigstore{
			IssuerMatch:              exactM("{{ .Context.iss }}"),
			IdentityMatch:            exactM("{{ .Context.who }}"),
			SourceRepositoryUriMatch: exactM("{{ .Context.repo }}"),
		},
		Matchers: []*sapi.Matcher{
			{Kind: &sapi.Matcher_String_{String_: exactM("{{ .Context.extra }}")}},
		},
	}
	key := &sapi.Identity{Key: &sapi.IdentityKey{IdMatch: exactM("{{ .Context.kid }}")}}

	ctx := map[string]any{
		"iss": "https://issuer", "who": "user@example.com",
		"repo": "https://github.com/o/r", "extra": "matched", "kid": "k1",
	}
	out, err := resolvePolicyIdentities([]*sapi.Identity{id, key}, ctx)
	require.NoError(t, err)

	ss := out[0].GetSigstore()
	require.Equal(t, "https://issuer", ss.GetIssuerMatch().GetExact())
	require.Equal(t, "user@example.com", ss.GetIdentityMatch().GetExact())
	require.Equal(t, "https://github.com/o/r", ss.GetSourceRepositoryUriMatch().GetExact())
	require.Equal(t, "matched", out[0].GetMatchers()[0].GetString_().GetExact())
	require.Equal(t, "k1", out[1].GetKey().GetIdMatch().GetExact())
}

// TestResolvePolicyIdentitiesStatic: a matcher with no template is unchanged
// (fast path), proving the static-matcher case still works.
func TestResolvePolicyIdentitiesStatic(t *testing.T) {
	t.Parallel()
	const lit = "https://github.com/o/r"
	id := &sapi.Identity{Sigstore: &sapi.IdentitySigstore{SourceRepositoryUriMatch: exactM(lit)}}
	out, err := resolvePolicyIdentities([]*sapi.Identity{id}, nil)
	require.NoError(t, err)
	require.Equal(t, lit, out[0].GetSigstore().GetSourceRepositoryUriMatch().GetExact())
}

// TestResolvePolicyIdentitiesMissing: a referenced-but-absent key fails closed.
func TestResolvePolicyIdentitiesMissing(t *testing.T) {
	t.Parallel()
	id := &sapi.Identity{Sigstore: &sapi.IdentitySigstore{IssuerMatch: exactM("{{ .Context.absent }}")}}
	_, err := resolvePolicyIdentities([]*sapi.Identity{id}, map[string]any{})
	require.Error(t, err)
}

// TestResolvePolicyIdentitiesNoMutation: the shared input proto is cloned, not
// mutated; its template survives resolution.
func TestResolvePolicyIdentitiesNoMutation(t *testing.T) {
	t.Parallel()
	id := &sapi.Identity{Sigstore: &sapi.IdentitySigstore{SourceRepositoryUriMatch: exactM("{{ .Context.repo }}")}}
	_, err := resolvePolicyIdentities([]*sapi.Identity{id}, map[string]any{"repo": "https://github.com/o/r"})
	require.NoError(t, err)
	require.Equal(t, "{{ .Context.repo }}", id.GetSigstore().GetSourceRepositoryUriMatch().GetExact())
}

// TestResolvePolicyIdentitiesEmpty: empty slice is a no-op.
func TestResolvePolicyIdentitiesEmpty(t *testing.T) {
	t.Parallel()
	out, err := resolvePolicyIdentities(nil, map[string]any{"x": "y"})
	require.NoError(t, err)
	require.Empty(t, out)
}
