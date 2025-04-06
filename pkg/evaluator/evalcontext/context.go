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
type EvaluationContextKey struct{}
type EvaluationContext struct {
	Subject attestation.Subject
	Policy  *api.Policy
}
