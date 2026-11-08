// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package evalcontext

import (
	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"
	sapi "github.com/policylabs/signer/api/v1"
)

// The evaluation context is the data structure we pass to the evaluators
// in the context. This lets implementation have access to more data while
// keeping the function signatures scoped to the minimun elements needed.
//
// The evaluation context data travels in this options set after being
// assembled and precomputed by the verifier from the policy data and
// external definitions.
type (
	EvaluationContextKey struct{}
	EvaluationContext    struct {
		// Subject under evaluation
		Subject attestation.Subject

		// Policy in effect
		Policy *papi.Policy

		// Context definitions as distilled through inheritance
		Context map[string]*papi.ContextVal

		// Context values from evaluation invocation
		ContextValues map[string]any

		// ChainedSubjects is a precomputed chain that informs the
		// policy evaluator how the subject was obtained, typically
		// by the policy set.
		ChainedSubjects []*papi.ChainedSubject
		// Chain is the chain the evaluation followed to reach Subject,
		// one hop per link, outermost first: the policy set's hops, then
		// the policy's own. Each hop keeps the predicate its selector
		// read, so a tenet can compare what it finds at the end of the
		// chain with what the chain was read from.
		Chain []ChainHop

		// Recognized identities for attestation validation.
		Identities []*sapi.Identity

		// Predicates is the policy's evidence once it is collected: the
		// predicates admitted by the signer identities, narrowed to the
		// policy's predicate types. It is nil until then, so an expression
		// evaluated earlier (a dynamic context value) cannot read it; an
		// empty slice means the evidence was collected and none survived.
		Predicates []attestation.Predicate
	}

	// ChainHop is one link of a followed chain: the record of the hop, as
	// the results carry it, and the predicate the hop's selector read.
	ChainHop struct {
		Record    *papi.ChainedSubject
		Predicate attestation.Predicate
	}
)

// Record returns the hops' records, the chain as the results carry it.
func Record(hops []ChainHop) []*papi.ChainedSubject {
	ret := make([]*papi.ChainedSubject, 0, len(hops))
	for _, hop := range hops {
		ret = append(ret, hop.Record)
	}
	return ret
}
