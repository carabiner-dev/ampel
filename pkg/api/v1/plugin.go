// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"reflect"

	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
)

type Capability string

var (
	CapabilityPredicateParser          = Capability("PredicateParser")
	CapabilityEnvelopeParser           = Capability("EnvelopeParser")
	CapabilityStatementParser          = Capability("StatementParser")
	CapabilityPredicateTransformer     = Capability("PredicateTransformer")
	CapabilitySignatureVerifier        = Capability("SignatureVerifier")
	CapabilityEvalEngineFunctionPlugin = Capability("EvalEngineFunctionPlugin")
	CapabilityEvalEngineDataPlugin     = Capability("EvalEngineDataPlugin")
)

var Capabilities = map[Capability]reflect.Type{
	CapabilityPredicateParser:          reflect.TypeOf((*PredicateParser)(nil)),
	CapabilityEnvelopeParser:           reflect.TypeOf((*EnvelopeParser)(nil)),
	CapabilityStatementParser:          reflect.TypeOf((*StatementParser)(nil)),
	CapabilityPredicateTransformer:     reflect.TypeOf((*PredicateTransformer)(nil)),
	CapabilitySignatureVerifier:        reflect.TypeOf((*SignatureVerifier)(nil)),
	CapabilityEvalEngineFunctionPlugin: reflect.TypeOf((*EvalEngineFunctionPlugin)(nil)),
	CapabilityEvalEngineDataPlugin:     reflect.TypeOf((*EvalEngineDataPlugin)(nil)),
}

type Plugin interface {
	Capabilities() []Capability
}

func PluginHasCapability(capability Capability, plugin Plugin) bool {
	pluginType := reflect.TypeOf(plugin)
	if _, ok := Capabilities[capability]; !ok {
		return false
	}
	return pluginType.Implements(Capabilities[capability])
}

type PredicateParser interface{}
type EnvelopeParser interface{}
type StatementParser interface{}
type PredicateTransformer interface{}
type SignatureVerifier interface{}

type EvalEngineFunctionPlugin interface {
	CanRegisterFunctionsFor(class.Class) bool
}
type EvalEngineDataPlugin interface {
	CanRegisterDataFor(class.Class) bool
}
