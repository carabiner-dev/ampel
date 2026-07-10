// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"errors"
	"reflect"
	"slices"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/carabiner-dev/ampel/pkg/evaluator/plugins/cvss"
)

// OSVType is the CEL receiver type backing the `osv` variable.
var OSVType = cel.ObjectType("osv", traits.ReceiverType)

type OSVTool struct{}

// Functions returns the CEL member functions exposed on the `osv` object:
//
//	osv.vulns(data)        -> list  : every vulnerability, flattened across
//	                                  results -> packages -> vulnerabilities
//	osv.ids(data)          -> list  : the id of every vulnerability
//	osv.aliases(vuln)      -> list  : a vulnerability's id plus its aliases
//	osv.matchesID(vuln, id)-> bool  : true if id equals the vuln's id or an alias
//	osv.cvss(vuln)         -> double: highest CVSS base score across the vuln's
//	                                  severity vectors (0 when none parse)
//
// The data argument may be an OSV results object or a whole predicate (`data`
// key is unwrapped automatically), so both osv.vulns(predicate) and
// osv.vulns(predicate.data) work.
func (t *OSVTool) Functions() []cel.EnvOption {
	return []cel.EnvOption{
		dynListFn("vulns", flattenVulns),
		stringListFn("ids", vulnIDs),
		stringListFn("aliases", aliasesOf),
		cel.Function("matchesID",
			cel.MemberOverload("osv_matchesid_binding",
				[]*cel.Type{OSVType, cel.DynType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					if len(args) != 3 {
						return types.NewErrFromString("osv.matchesID requires a vulnerability and an id")
					}
					id, ok := args[2].Value().(string)
					if !ok {
						return types.NewErrFromString("osv.matchesID: id must be a string")
					}
					return types.Bool(slices.Contains(aliasesOf(toGo(args[1])), id))
				}),
			),
		),
		cel.Function("cvss",
			cel.MemberOverload("osv_cvss_binding",
				[]*cel.Type{OSVType, cel.DynType}, cel.DoubleType,
				cel.BinaryBinding(func(_ ref.Val, rhs ref.Val) ref.Val {
					return types.Double(bestCVSS(toGo(rhs)))
				}),
			),
		),
	}
}

// dynListFn registers an (osv, dyn) -> list<dyn> member function.
func dynListFn(name string, fn func(any) []any) cel.EnvOption {
	return cel.Function(name,
		cel.MemberOverload("osv_"+name+"_binding",
			[]*cel.Type{OSVType, cel.DynType}, cel.ListType(cel.DynType),
			cel.BinaryBinding(func(_ ref.Val, rhs ref.Val) ref.Val {
				return types.DefaultTypeAdapter.NativeToValue(fn(toGo(rhs)))
			}),
		),
	)
}

// stringListFn registers an (osv, dyn) -> list<string> member function.
func stringListFn(name string, fn func(any) []string) cel.EnvOption {
	return cel.Function(name,
		cel.MemberOverload("osv_"+name+"_binding",
			[]*cel.Type{OSVType, cel.DynType}, cel.ListType(cel.StringType),
			cel.BinaryBinding(func(_ ref.Val, rhs ref.Val) ref.Val {
				return types.DefaultTypeAdapter.NativeToValue(fn(toGo(rhs)))
			}),
		),
	)
}

// OSV traversal (operates on the native JSON shape produced by protojson).

// osvResults returns the OSV results object, unwrapping a predicate `data` key
// when present so callers may pass either a predicate or its data.
func osvResults(data any) map[string]any {
	m, ok := data.(map[string]any)
	if !ok {
		return nil
	}
	if _, ok := m["results"]; ok {
		return m
	}
	if inner, ok := m["data"].(map[string]any); ok {
		if _, ok := inner["results"]; ok {
			return inner
		}
	}
	return nil
}

// flattenVulns collapses results -> packages -> vulnerabilities into one list.
func flattenVulns(data any) []any {
	out := []any{}
	root := osvResults(data)
	if root == nil {
		return out
	}
	results, ok := root["results"].([]any)
	if !ok {
		return out
	}
	for _, r := range results {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		packages, ok := rm["packages"].([]any)
		if !ok {
			continue
		}
		for _, p := range packages {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			if vulns, ok := pm["vulnerabilities"].([]any); ok {
				out = append(out, vulns...)
			}
		}
	}
	return out
}

// vulnIDs returns the id of every vulnerability in the document.
func vulnIDs(data any) []string {
	out := []string{}
	for _, v := range flattenVulns(data) {
		if vm, ok := v.(map[string]any); ok {
			if id, ok := vm["id"].(string); ok && id != "" {
				out = append(out, id)
			}
		}
	}
	return out
}

// aliasesOf returns a vulnerability's id followed by its declared aliases.
func aliasesOf(vuln any) []string {
	out := []string{}
	vm, ok := vuln.(map[string]any)
	if !ok {
		return out
	}
	if id, ok := vm["id"].(string); ok && id != "" {
		out = append(out, id)
	}
	if aliases, ok := vm["aliases"].([]any); ok {
		for _, a := range aliases {
			if s, ok := a.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// bestCVSS returns the highest CVSS base score across the vulnerability's
// severity vectors, or 0 when none are present or parseable.
func bestCVSS(vuln any) float64 {
	vm, ok := vuln.(map[string]any)
	if !ok {
		return 0
	}
	severities, ok := vm["severity"].([]any)
	if !ok {
		return 0
	}
	best := 0.0
	for _, s := range severities {
		sm, ok := s.(map[string]any)
		if !ok {
			continue
		}
		vector, ok := sm["score"].(string)
		if !ok || vector == "" {
			continue
		}
		if score, err := cvss.Score(vector); err == nil && score > best {
			best = score
		}
	}
	return best
}

// toGo converts a CEL value (a structpb-backed map/list from predicate data)
// into native Go values (map[string]any / []any / primitives).
func toGo(v ref.Val) any {
	if v == nil {
		return nil
	}
	if native, err := v.ConvertToNative(reflect.TypeFor[*structpb.Value]()); err == nil {
		if sv, ok := native.(*structpb.Value); ok {
			return sv.AsInterface()
		}
	}
	return v.Value()
}

// CEL ref.Val + Library plumbing.

func (t *OSVTool) ConvertToType(typeVal ref.Type) ref.Val {
	if typeVal == types.TypeType {
		return OSVType
	}
	return types.NewErr("type conversion not allowed for osv")
}

func (*OSVTool) Type() ref.Type { return OSVType }

func (*OSVTool) Equal(_ ref.Val) ref.Val {
	return types.NewErr("objects cannot be compared")
}

func (t *OSVTool) Value() any { return t }

func (*OSVTool) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, errors.New("osv cannot be converted to native")
}

type TypeAdapter struct{}

func (TypeAdapter) NativeToValue(value any) ref.Val {
	if val, ok := value.(OSVTool); ok {
		return &val
	}
	return types.DefaultTypeAdapter.NativeToValue(value)
}

func (t *OSVTool) CompileOptions() []cel.EnvOption {
	funcs := t.Functions()
	ret := make([]cel.EnvOption, 0, 3+len(funcs))
	ret = append(ret,
		cel.Types(OSVType),
		cel.CustomTypeAdapter(&TypeAdapter{}),
		cel.Variable("osv", OSVType),
	)
	ret = append(ret, funcs...)
	return ret
}

func (*OSVTool) ProgramOptions() []cel.ProgramOption { return nil }
