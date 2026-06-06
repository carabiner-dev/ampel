// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package verifier

import (
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/envelope/bundle"
	papi "github.com/carabiner-dev/policy/api/v1"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	acontext "github.com/carabiner-dev/ampel/pkg/context"
)

// TestSourceRepositoryURIEndToEnd exercises the whole chain against a real
// GitHub Actions keyless bundle: the collector captures the source repository
// URI (OID 1.3.6.1.4.1.57264.1.12) from the cert, and ampel's CheckIdentities
// matches it via source_repository_uri_match. Verification hits the sigstore
// trust root over TUF, so it needs network.
func TestSourceRepositoryURIEndToEnd(t *testing.T) {
	const issuer = "https://token.actions.githubusercontent.com"
	const repo = "https://github.com/sigstore/sigstore-js"

	exact := func(s string) *sapi.StringMatcher {
		return &sapi.StringMatcher{Kind: &sapi.StringMatcher_Exact{Exact: s}}
	}
	// A policy identity pinning the workflow issuer AND the origin repo.
	policy := func(srcRepo string) []*sapi.Identity {
		return []*sapi.Identity{{
			Sigstore: &sapi.IdentitySigstore{
				IssuerMatch:              exact(issuer),
				SourceRepositoryUriMatch: exact(srcRepo),
			},
		}}
	}

	envs, err := (&bundle.Parser{}).ParseFile("testdata/github-actions-bundle.json")
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	di := defaultIplementation{}
	check := func(ids []*sapi.Identity) bool {
		allow, _, _, err := di.CheckIdentities(
			t.Context(), &VerificationOptions{}, ids, []attestation.Envelope{envs[0]},
		)
		require.NoError(t, err)
		return allow
	}

	// Correct issuer + correct origin repo: the attestation is accepted.
	require.True(t, check(policy(repo)), "expected the real source repo to match")

	// Correct issuer + wrong origin repo: AND semantics fail closed.
	require.False(t, check(policy("https://github.com/evil/repo")), "wrong source repo must not match")
}

// TestSourceRepositoryURIDynamicEndToEnd exercises the dynamic path: the
// published policy bakes in the signer issuer and leaves the origin repo as a
// {{ .Context.x }} template; the verifier supplies the repo at runtime (as
// -x source_repo=... would). resolvePolicyIdentities fills the matcher BEFORE
// CheckIdentities, so the constraint stays AND-ed inside the identity and fails
// closed.
func TestSourceRepositoryURIDynamicEndToEnd(t *testing.T) {
	const issuer = "https://token.actions.githubusercontent.com"
	const repo = "https://github.com/sigstore/sigstore-js"

	exact := func(s string) *sapi.StringMatcher {
		return &sapi.StringMatcher{Kind: &sapi.StringMatcher_Exact{Exact: s}}
	}
	// The published policy: issuer baked in, repo supplied via context.
	published := func() []*sapi.Identity {
		return []*sapi.Identity{{
			Sigstore: &sapi.IdentitySigstore{
				IssuerMatch:              exact(issuer),
				SourceRepositoryUriMatch: exact("{{ .Context.source_repo }}"),
			},
		}}
	}

	envs, err := (&bundle.Parser{}).ParseFile("testdata/github-actions-bundle.json")
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	di := defaultIplementation{}
	checkWith := func(ctxVals map[string]any) (bool, error) {
		resolved, err := resolvePolicyIdentities(published(), ctxVals)
		if err != nil {
			return false, err
		}
		allow, _, _, err := di.CheckIdentities(
			t.Context(), &VerificationOptions{}, resolved, []attestation.Envelope{envs[0]},
		)
		require.NoError(t, err)
		return allow, nil
	}

	// Verifier supplies the correct repo -> template resolves -> accepted.
	allow, err := checkWith(map[string]any{"source_repo": repo})
	require.NoError(t, err)
	require.True(t, allow, "verifier-supplied correct repo must match")

	// Verifier supplies a wrong repo -> fails closed (AND with the baked issuer).
	allow, err = checkWith(map[string]any{"source_repo": "https://github.com/evil/repo"})
	require.NoError(t, err)
	require.False(t, allow, "verifier-supplied wrong repo must not match")

	// Verifier supplies nothing -> resolution errors (fail closed), not match-anything.
	_, err = checkWith(map[string]any{})
	require.Error(t, err, "missing required context value must error, not silently pass")

	// The shared policy proto is never mutated: resolving a captured identity
	// leaves the original template in place (clone, don't mutate).
	original := published()
	_, err = resolvePolicyIdentities(original, map[string]any{"source_repo": repo})
	require.NoError(t, err)
	require.Equal(t,
		"{{ .Context.source_repo }}",
		original[0].GetSigstore().GetSourceRepositoryUriMatch().GetExact(),
		"resolvePolicyIdentities must not mutate the shared policy identity",
	)
}

// TestSourceRepositoryURIDynamicFullPath exercises the dynamic source-repository
// binding through the COMPLETE ampel.Verify orchestration (not just the
// resolvePolicyIdentities + CheckIdentities helpers, as the tests above do).
//
// A published policy bakes in the workflow issuer and leaves the origin repo as
// a {{ .Context.source_repo }} template; the verifier supplies the repo at
// runtime via a context provider (the same StringMapList the `-x source_repo=...`
// CLI flag builds). ampel.Verify assembles the context, resolves the template in
// the policy identity, then runs CheckIdentities. The constraint is AND-ed inside
// the signer identity, so it fails closed.
//
// This goes through the real entry point: ampel.Verify -> VerifySubjectWithPolicySet
// -> VerifySubjectWithPolicy, with the bundle fed via opts.Attestations (no
// collector). Verifying the keyless bundle hits the sigstore trust root over TUF,
// so it needs network (e2e).
//
// Path facts worth knowing (discovered while writing this):
//   - The subject MUST carry the bundle statement's digest. GatherAttestations
//     filters opts.Attestations by subject hash BEFORE CheckIdentities runs; a
//     mismatched subject empties the set and collapses the correct/wrong-repo
//     cases. We derive the subject straight from the bundle statement.
//   - Correct repo -> identity admitted -> the lone `Code:"true"` tenet passes
//     -> ResultSet status PASS.
//   - Wrong repo -> CheckIdentities admits nothing -> the policy is failed with
//     "attestation identity validation failed" -> ResultSet status FAIL.
//   - Missing required source_repo -> AssembleEvalContextValues errors ("context
//     value source_repo is required but not set"), which ampel.Verify surfaces as
//     an error (fail closed), NOT a FAIL result.
func TestSourceRepositoryURIDynamicFullPath(t *testing.T) {
	const issuer = "https://token.actions.githubusercontent.com"
	const repo = "https://github.com/sigstore/sigstore-js"

	exact := func(s string) *sapi.StringMatcher {
		return &sapi.StringMatcher{Kind: &sapi.StringMatcher_Exact{Exact: s}}
	}

	envs, err := (&bundle.Parser{}).ParseFile("testdata/github-actions-bundle.json")
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	env := envs[0]

	// Derive the subject from the bundle statement so its digest matches what
	// GatherAttestations filters on (otherwise the bundle is dropped before the
	// identity check and both branches become vacuous).
	subjects := env.GetStatement().GetSubjects()
	require.NotEmpty(t, subjects, "bundle statement must carry a subject")
	subject := subjects[0]

	// The published policy: issuer baked in, origin repo left as a context
	// template, source_repo declared as a required context value. One tenet that
	// passes once the attestation is admitted, so a PASS proves admission.
	buildPolicySet := func() *papi.PolicySet {
		return &papi.PolicySet{
			Id:   "dynamic-source-repo-set",
			Meta: &papi.PolicySetMeta{},
			Policies: []*papi.Policy{
				{
					Id:   "dynamic-source-repo-policy",
					Meta: &papi.Meta{},
					Context: map[string]*papi.ContextVal{
						"source_repo": {
							Type:     "string",
							Required: proto.Bool(true),
						},
					},
					Identities: []*sapi.Identity{
						{
							Sigstore: &sapi.IdentitySigstore{
								IssuerMatch:              exact(issuer),
								SourceRepositoryUriMatch: exact("{{ .Context.source_repo }}"),
							},
						},
					},
					Tenets: []*papi.Tenet{
						{Id: "admitted", Code: "true"},
					},
				},
			},
		}
	}

	// verify runs the full ampel.Verify with the given context provider values
	// (nil entry => provider omitted, i.e. source_repo unset).
	verify := func(t *testing.T, ctxVals []string) (papi.Results, error) {
		t.Helper()
		// New() supplies a Collector that returns ErrNoFetcherConfigured (handled
		// gracefully); the bundle survives via opts.Attestations.
		ampel, err := New()
		require.NoError(t, err)

		opts := NewVerificationOptions()
		opts.EnforceExpiration = false
		opts.Attestations = []attestation.Envelope{env}
		if ctxVals != nil {
			// Mirror buildContextProviders: -x values become a *StringMapList.
			l := acontext.StringMapList(ctxVals)
			opts.ContextProviders = []acontext.Provider{&l}
		}

		return ampel.Verify(t.Context(), &opts, buildPolicySet(), subject)
	}

	// 1. Correct repo supplied -> attestation admitted -> tenet passes -> PASS.
	t.Run("correct-repo-admitted", func(t *testing.T) {
		res, err := verify(t, []string{"source_repo:" + repo})
		require.NoError(t, err)
		require.Equal(t, papi.StatusPASS, res.GetStatus(),
			"correct verifier-supplied repo must admit the attestation and pass")
	})

	// 2. Wrong repo supplied -> CheckIdentities admits nothing -> policy fails
	//    with the identity-validation error -> FAIL.
	t.Run("wrong-repo-rejected", func(t *testing.T) {
		res, err := verify(t, []string{"source_repo:https://github.com/evil/repo"})
		require.NoError(t, err)
		require.Equal(t, papi.StatusFAIL, res.GetStatus(),
			"wrong verifier-supplied repo must reject the attestation and fail")

		// And confirm it failed on identity specifically, not the tenet.
		rs, ok := res.(*papi.ResultSet)
		require.True(t, ok, "expected a *papi.ResultSet")
		require.NotEmpty(t, rs.GetResults())
		var sawIdentityFailure bool
		for _, r := range rs.GetResults() {
			for _, er := range r.GetEvalResults() {
				if er.GetError().GetMessage() == "attestation identity validation failed" {
					sawIdentityFailure = true
				}
			}
		}
		require.True(t, sawIdentityFailure,
			"wrong repo must fail at identity validation, not at the tenet")
	})

	// 3. Required source_repo missing -> fail closed: ampel.Verify errors during
	//    context assembly rather than admitting or silently passing.
	t.Run("missing-repo-fails-closed", func(t *testing.T) {
		_, err := verify(t, nil)
		require.Error(t, err,
			"missing required source_repo must error (fail closed), not pass")
	})
}
