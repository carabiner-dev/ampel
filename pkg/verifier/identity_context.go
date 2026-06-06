// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"fmt"
	"strings"
	"text/template"

	sapi "github.com/carabiner-dev/signer/api/v1"
	"google.golang.org/protobuf/proto"
)

// resolvePolicyIdentities returns copies of the identities with {{ .Context.x }}
// templates in their StringMatcher values rendered from the context. It runs
// before CheckIdentities so the resolved value lands inside the identity (AND-ed)
// and fails closed: a missing context value errors, and the policy proto is
// cloned, never mutated.
func resolvePolicyIdentities(identities []*sapi.Identity, contextValues map[string]any) ([]*sapi.Identity, error) {
	if len(identities) == 0 {
		return identities, nil
	}
	data := struct{ Context map[string]any }{Context: contextValues}
	out := make([]*sapi.Identity, 0, len(identities))
	for _, id := range identities {
		clone, ok := proto.Clone(id).(*sapi.Identity)
		if !ok {
			return nil, fmt.Errorf("cloning identity %q", id.GetId())
		}
		for _, m := range identityStringMatchers(clone) {
			if err := renderStringMatcher(m, data); err != nil {
				return nil, fmt.Errorf("identity %q: %w", id.GetId(), err)
			}
		}
		out = append(out, clone)
	}
	return out, nil
}

// identityStringMatchers collects the StringMatchers an identity carries, across
// its per-variant convenience fields and the outer matcher slice.
func identityStringMatchers(id *sapi.Identity) []*sapi.StringMatcher {
	var ms []*sapi.StringMatcher
	if ss := id.GetSigstore(); ss != nil {
		ms = append(ms, ss.GetIssuerMatch(), ss.GetIdentityMatch(), ss.GetSourceRepositoryUriMatch())
	}
	if k := id.GetKey(); k != nil {
		ms = append(ms, k.GetIdMatch(), k.GetTypeMatch(), k.GetSigningFingerprintMatch())
	}
	if sp := id.GetSpiffe(); sp != nil {
		ms = append(ms, sp.GetSvidMatch(), sp.GetTrustDomainMatch(), sp.GetPathMatch())
	}
	for _, m := range id.GetMatchers() {
		ms = append(ms, m.GetString_())
	}
	out := ms[:0]
	for _, m := range ms {
		if m != nil {
			out = append(out, m)
		}
	}
	return out
}

// renderStringMatcher renders a Go template in the matcher's set value in place.
// Values without a template action are left untouched.
func renderStringMatcher(m *sapi.StringMatcher, data any) error {
	switch k := m.GetKind().(type) {
	case *sapi.StringMatcher_Exact:
		v, err := renderTemplate(k.Exact, data)
		if err != nil {
			return err
		}
		k.Exact = v
	case *sapi.StringMatcher_Regex:
		v, err := renderTemplate(k.Regex, data)
		if err != nil {
			return err
		}
		k.Regex = v
	case *sapi.StringMatcher_Prefix:
		v, err := renderTemplate(k.Prefix, data)
		if err != nil {
			return err
		}
		k.Prefix = v
	case *sapi.StringMatcher_Glob:
		v, err := renderTemplate(k.Glob, data)
		if err != nil {
			return err
		}
		k.Glob = v
	}
	return nil
}

func renderTemplate(s string, data any) (string, error) {
	if !strings.Contains(s, "{{") {
		return s, nil
	}
	tmpl, err := template.New("identity").Option("missingkey=error").Parse(s)
	if err != nil {
		return "", fmt.Errorf("parsing identity template %q: %w", s, err)
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, data); err != nil {
		return "", fmt.Errorf("resolving identity template %q: %w", s, err)
	}
	return b.String(), nil
}
