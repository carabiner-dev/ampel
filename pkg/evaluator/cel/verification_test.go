// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cel

import (
	"testing"

	"github.com/carabiner-dev/attestation"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// mockPredicate is a minimal attestation.Predicate for testing verification.
type mockPredicate struct {
	verification attestation.Verification
}

func (m *mockPredicate) GetType() attestation.PredicateType        { return "" }
func (m *mockPredicate) SetType(attestation.PredicateType) error   { return nil }
func (m *mockPredicate) GetParsed() any                            { return nil }
func (m *mockPredicate) GetData() []byte                           { return []byte("{}") }
func (m *mockPredicate) GetVerification() attestation.Verification { return m.verification }
func (m *mockPredicate) GetOrigin() attestation.Subject            { return nil }
func (m *mockPredicate) SetOrigin(attestation.Subject)             {}
func (m *mockPredicate) SetVerification(attestation.Verification)  {}

var _ attestation.Predicate = (*mockPredicate)(nil)

// newTestEnv creates a CEL environment with the predicate variable and
// matchesId function registered, mirroring the real evaluator setup.
func newTestEnv(t *testing.T) *cel.Env {
	t.Helper()
	vco := verificationCompileOptions()
	opts := make([]cel.EnvOption, 0, 1+len(vco))
	opts = append(opts, cel.Variable("predicate", cel.AnyType))
	opts = append(opts, vco...)
	env, err := cel.NewEnv(opts...)
	require.NoError(t, err)
	return env
}

// testPredicateVars builds a vars map with a PredicateVal for the given mock.
func testPredicateVars(pred attestation.Predicate) map[string]any {
	sv, _ := structpb.NewValue(map[string]any{ //nolint:errcheck // test helper with static input
		"predicate_type": "",
		"data":           map[string]any{},
	})
	return map[string]any{
		"predicate": NewPredicateVal(sv, pred),
	}
}

func evalBool(t *testing.T, env *cel.Env, code string, vars map[string]any) bool {
	t.Helper()
	ast, iss := env.Compile(code)
	require.NoError(t, iss.Err(), "compile %q", code)

	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	require.NoError(t, err)

	result, _, err := program.Eval(vars)
	require.NoError(t, err, "eval %q", code)

	b, ok := result.Value().(bool)
	require.True(t, ok, "expected bool from %q, got %T", code, result.Value())
	return b
}

func evalErr(t *testing.T, env *cel.Env, code string, vars map[string]any) {
	t.Helper()
	ast, iss := env.Compile(code)
	require.NoError(t, iss.Err(), "compile %q", code)

	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	require.NoError(t, err)

	_, _, err = program.Eval(vars)
	require.Error(t, err, "expected error from %q", code)
}

func TestPredicateVerificationMatchesIdSigstore(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	pred := &mockPredicate{
		verification: &sapi.Verification{
			Signature: &sapi.SignatureVerification{
				Verified: true,
				Identities: []*sapi.Identity{
					{
						Sigstore: &sapi.IdentitySigstore{
							Issuer:   "https://accounts.google.com",
							Identity: "user@example.com",
						},
					},
				},
			},
		},
	}

	vars := testPredicateVars(pred)

	t.Run("matching", func(t *testing.T) {
		t.Parallel()
		got := evalBool(t, env, `predicate.verification.matchesId("sigstore::https://accounts.google.com::user@example.com")`, vars)
		require.True(t, got)
	})

	t.Run("non-matching", func(t *testing.T) {
		t.Parallel()
		got := evalBool(t, env, `predicate.verification.matchesId("sigstore::https://accounts.google.com::other@example.com")`, vars)
		require.False(t, got)
	})
}

func TestPredicateVerificationMatchesIdKey(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	pred := &mockPredicate{
		verification: &sapi.Verification{
			Signature: &sapi.SignatureVerification{
				Verified: true,
				Identities: []*sapi.Identity{
					{
						Key: &sapi.IdentityKey{
							Id:   "SHA256:abc123",
							Type: "ssh-ed25519",
						},
					},
				},
			},
		},
	}

	vars := testPredicateVars(pred)

	got := evalBool(t, env, `predicate.verification.matchesId("key::ssh-ed25519::SHA256:abc123")`, vars)
	require.True(t, got)
}

func TestPredicateVerificationMatchesIdNilDefault(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	// nil predicate → default verification (verified=false)
	vars := testPredicateVars(nil)

	got := evalBool(t, env, `predicate.verification.matchesId("sigstore::https://accounts.google.com::user@example.com")`, vars)
	require.False(t, got)
}

func TestPredicateVerificationMatchesIdInvalidSlug(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	pred := &mockPredicate{
		verification: &sapi.Verification{
			Signature: &sapi.SignatureVerification{
				Verified: true,
			},
		},
	}
	vars := testPredicateVars(pred)

	evalErr(t, env, `predicate.verification.matchesId("invalid-slug-no-separator")`, vars)
}

func TestPredicateVerificationFieldAccess(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	t.Run("verified true", func(t *testing.T) {
		t.Parallel()
		pred := &mockPredicate{
			verification: &sapi.Verification{
				Signature: &sapi.SignatureVerification{
					Verified: true,
					Identities: []*sapi.Identity{
						{
							Sigstore: &sapi.IdentitySigstore{
								Issuer:   "https://accounts.google.com",
								Identity: "user@example.com",
							},
						},
					},
				},
			},
		}
		vars := testPredicateVars(pred)
		got := evalBool(t, env, `predicate.verification.verified == true`, vars)
		require.True(t, got)
	})

	t.Run("verified false (nil predicate)", func(t *testing.T) {
		t.Parallel()
		vars := testPredicateVars(nil)
		got := evalBool(t, env, `predicate.verification.verified == false`, vars)
		require.True(t, got)
	})

	t.Run("identities access", func(t *testing.T) {
		t.Parallel()
		pred := &mockPredicate{
			verification: &sapi.Verification{
				Signature: &sapi.SignatureVerification{
					Verified: true,
					Identities: []*sapi.Identity{
						{
							Sigstore: &sapi.IdentitySigstore{
								Issuer:   "https://accounts.google.com",
								Identity: "user@example.com",
							},
						},
					},
				},
			},
		}
		vars := testPredicateVars(pred)
		got := evalBool(t, env, `predicate.verification.identities[0].sigstore.identity == "user@example.com"`, vars)
		require.True(t, got)
	})
}

func TestPredicateDataAccess(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	// Verify that non-verification fields still work through PredicateVal
	sv, err := structpb.NewValue(map[string]any{
		"predicate_type": "https://example.com/predicate/v1",
		"data":           map[string]any{"key": "value"},
	})
	require.NoError(t, err)

	vars := map[string]any{
		"predicate": NewPredicateVal(sv, nil),
	}

	got := evalBool(t, env, `predicate.predicate_type == "https://example.com/predicate/v1"`, vars)
	require.True(t, got)

	got = evalBool(t, env, `predicate.data.key == "value"`, vars)
	require.True(t, got)
}
