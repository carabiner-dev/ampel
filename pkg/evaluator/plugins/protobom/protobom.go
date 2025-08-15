// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package protobom

import (
	"bytes"

	"github.com/carabiner-dev/attestation"
	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/google/cel-go/cel"
	"github.com/protobom/cel/pkg/elements"
	"github.com/protobom/cel/pkg/library"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/sirupsen/logrus"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/collector/predicate/cyclonedx"
	"github.com/carabiner-dev/collector/predicate/spdx"
)

func New() *Plugin {
	return &Plugin{}
}

type Plugin struct{}

func (h *Plugin) Capabilities() []api.Capability {
	return []api.Capability{
		api.CapabilityEvalEnginePlugin,
	}
}

func (p *Plugin) CanRegisterFor(c class.Class) bool {
	return c.Name() == "cel"
}

func (p *Plugin) Library() cel.EnvOption {
	return library.NewProtobom().EnvOption()
}

func (p *Plugin) VarValues(_ *papi.Policy, _ attestation.Subject, preds []attestation.Predicate) map[string]any {
	sbomList := []any{}
	r := reader.New()
	logrus.Debugf("Inserting protobom vars (from %d predicates)", len(preds))
	for _, pred := range preds {
		if pred.GetType() != spdx.PredicateType && pred.GetType() != cyclonedx.PredicateType {
			continue
		}
		doc, err := r.ParseStream(bytes.NewReader(pred.GetData()))
		if err != nil {
			// we cannot return errs so..
			continue
		}
		sbomList = append(sbomList, &elements.Document{
			Document: doc,
		})
	}

	return map[string]any{
		"protobom": elements.Protobom{},
		"sboms":    sbomList,
	}
}
