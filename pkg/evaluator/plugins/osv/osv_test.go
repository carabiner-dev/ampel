// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"
)

// sampleData mirrors the JSON shape of an OSV results predicate: two
// vulnerabilities on one package, the first carrying an alias and a critical
// CVSS vector, the second a medium one.
func sampleData() map[string]any {
	return map[string]any{
		"results": []any{
			map[string]any{
				"source": map[string]any{"path": "go.mod", "type": "lockfile"},
				"packages": []any{
					map[string]any{
						"package": map[string]any{"name": "github.com/x/y", "ecosystem": "Go"},
						"vulnerabilities": []any{
							map[string]any{
								"id":      "GHSA-aaaa-bbbb-cccc",
								"aliases": []any{"CVE-2026-0001"},
								"severity": []any{
									map[string]any{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
								},
							},
							map[string]any{
								"id": "CVE-2026-0002",
								"severity": []any{
									map[string]any{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"},
								},
							},
						},
					},
				},
			},
		},
	}
}

func run(t *testing.T, expr string, data any) any {
	t.Helper()
	p := New()
	env, err := cel.NewEnv(p.Library(), cel.Variable("data", cel.DynType))
	require.NoError(t, err)
	ast, iss := env.Compile(expr)
	require.NoError(t, iss.Err(), "compile %q", expr)
	program, err := env.Program(ast)
	require.NoError(t, err)
	vars := p.VarValues(nil, nil, nil)
	vars["data"] = data
	result, _, err := program.Eval(vars)
	require.NoError(t, err, "eval %q", expr)
	return result.Value()
}

func TestVulnsAndIDs(t *testing.T) {
	t.Parallel()
	require.Equal(t, int64(2), run(t, "size(osv.vulns(data))", sampleData()))
	require.Equal(t, true, run(t, "osv.ids(data) == ['GHSA-aaaa-bbbb-cccc', 'CVE-2026-0002']", sampleData()))
	// The returned vulns are usable objects.
	require.Equal(t, "GHSA-aaaa-bbbb-cccc", run(t, "osv.vulns(data)[0].id", sampleData()))
}

func TestAliasesAndMatchesID(t *testing.T) {
	t.Parallel()
	require.Equal(t, true, run(t, "osv.aliases(osv.vulns(data)[0]) == ['GHSA-aaaa-bbbb-cccc', 'CVE-2026-0001']", sampleData()))
	// Match by primary id and by alias, and reject a non-match.
	require.Equal(t, true, run(t, "osv.matchesID(osv.vulns(data)[0], 'GHSA-aaaa-bbbb-cccc')", sampleData()))
	require.Equal(t, true, run(t, "osv.matchesID(osv.vulns(data)[0], 'CVE-2026-0001')", sampleData()))
	require.Equal(t, false, run(t, "osv.matchesID(osv.vulns(data)[0], 'CVE-9999-9999')", sampleData()))
	// The alias-aware form composes into a document-level check.
	require.Equal(t, true, run(t, "osv.vulns(data).exists(v, osv.matchesID(v, 'CVE-2026-0001'))", sampleData()))
}

func TestCVSS(t *testing.T) {
	t.Parallel()
	require.InDelta(t, 9.8, run(t, "osv.cvss(osv.vulns(data)[0])", sampleData()), 0.05)
	// A realistic policy: any fixable-or-not critical present.
	require.Equal(t, true, run(t, "osv.vulns(data).exists(v, osv.cvss(v) >= 9.0)", sampleData()))
	require.Equal(t, false, run(t, "osv.vulns(data).exists(v, osv.cvss(v) >= 9.0 && osv.matchesID(v, 'CVE-2026-0002'))", sampleData()))
}

func TestUnwrapsPredicate(t *testing.T) {
	t.Parallel()
	// Passing a whole predicate (with a data key) works the same as its data.
	pred := map[string]any{
		"predicate_type": "https://ossf.github.io/osv-schema/results@v1",
		"data":           sampleData(),
	}
	require.Equal(t, int64(2), run(t, "size(osv.vulns(data))", pred))
}

func TestEmptyAndMalformed(t *testing.T) {
	t.Parallel()
	require.Equal(t, int64(0), run(t, "size(osv.vulns(data))", map[string]any{}))
	require.Equal(t, int64(0), run(t, "size(osv.ids(data))", map[string]any{"results": []any{}}))
	require.InDelta(t, 0.0, run(t, "osv.cvss({})", sampleData()), 0.001)
}
