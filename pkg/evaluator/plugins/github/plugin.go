// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"github.com/carabiner-dev/attestation"
	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/google/cel-go/cel"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
)

type Plugin struct {
	Util *GitHubUtil
}

func New() *Plugin {
	return &Plugin{
		Util: &GitHubUtil{},
	}
}

func (h *Plugin) Capabilities() []api.Capability {
	return []api.Capability{
		api.CapabilityEvalEnginePlugin,
	}
}

func (h *Plugin) CanRegisterFor(c class.Class) bool {
	return c.Name() == "cel"
}

func (h *Plugin) Library() cel.EnvOption {
	return cel.Lib(h.Util)
}

func (h *Plugin) VarValues(_ *papi.Policy, _ attestation.Subject, _ []attestation.Predicate) map[string]any {
	return map[string]any{
		"github": h.Util,
	}
}
