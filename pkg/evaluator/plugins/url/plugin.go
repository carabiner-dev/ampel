// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package url

import (
	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/google/cel-go/cel"
)

type Plugin struct {
	Tool *UrlTool
}

func New() *Plugin {
	return &Plugin{
		Tool: &UrlTool{},
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
	return cel.Lib(h.Tool)
}

func (h *Plugin) VarValues(_ *api.Policy, _ attestation.Subject, _ []attestation.Predicate) map[string]any {
	return map[string]any{
		"url": h.Tool,
	}
}
