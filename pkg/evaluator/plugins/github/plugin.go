// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/google/cel-go/cel"
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

func (h *Plugin) VarValues() map[string]any {
	return map[string]any{
		"github": h.Util,
	}
}
