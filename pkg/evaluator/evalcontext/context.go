// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package evalcontext

import (
	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
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
		Policy *api.Policy
		// Context definitions as distilled through inheritance
		Context map[string]*api.ContextVal
		// Context values from evaluation invocation
		ContextValues map[string]any
	}
)
