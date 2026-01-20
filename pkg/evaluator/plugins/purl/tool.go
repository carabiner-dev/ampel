// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package purl

import (
	"errors"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	packageurl "github.com/package-url/packageurl-go"
)

type PurlTool struct{}

var PurlType = cel.ObjectType("purl")

func (pt *PurlTool) Functions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function(
			"parse",
			cel.MemberOverload(
				"purl_parse_binding",
				[]*cel.Type{PurlType, cel.StringType}, cel.MapType(cel.StringType, cel.AnyType),
				cel.BinaryBinding(parse),
			),
		),
		cel.Function(
			"packageType",
			cel.MemberOverload(
				"purl_type_binding",
				[]*cel.Type{PurlType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(purlType),
			),
		),
		cel.Function(
			"namespace",
			cel.MemberOverload(
				"purl_namespace_binding",
				[]*cel.Type{PurlType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(namespace),
			),
		),
		cel.Function(
			"name",
			cel.MemberOverload(
				"purl_name_binding",
				[]*cel.Type{PurlType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(name),
			),
		),
		cel.Function(
			"version",
			cel.MemberOverload(
				"purl_version_binding",
				[]*cel.Type{PurlType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(version),
			),
		),
		cel.Function(
			"qualifiers",
			cel.MemberOverload(
				"purl_qualifiers_binding",
				[]*cel.Type{PurlType, cel.StringType}, cel.MapType(cel.StringType, cel.StringType),
				cel.BinaryBinding(qualifiers),
			),
		),
		cel.Function(
			"subpath",
			cel.MemberOverload(
				"purl_subpath_binding",
				[]*cel.Type{PurlType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(subpath),
			),
		),
	}
}

var parse = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		parsed, err := packageurl.FromString(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}

		// Convert qualifiers to map[string]string
		qualMap := make(map[string]string)
		for _, q := range parsed.Qualifiers {
			qualMap[q.Key] = q.Value
		}

		// Create a map with all PURL components
		result := map[string]any{
			"type":      parsed.Type,
			"namespace": parsed.Namespace,
			"name":      parsed.Name,
			"version":   parsed.Version,
			"subpath":   parsed.Subpath,
		}

		// Convert qualifiers to CEL-compatible map
		reg, err := types.NewRegistry()
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		result["qualifiers"] = types.NewStringStringMap(reg, qualMap)

		return types.NewDynamicMap(reg, result)

	default:
		return types.NewErrFromString("unsupported type for PURL parse")
	}
}

var purlType = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		parsed, err := packageurl.FromString(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		return types.String(parsed.Type)
	default:
		return types.NewErrFromString("unsupported type for PURL type extraction")
	}
}

var namespace = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		parsed, err := packageurl.FromString(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		return types.String(parsed.Namespace)
	default:
		return types.NewErrFromString("unsupported type for PURL namespace extraction")
	}
}

var name = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		parsed, err := packageurl.FromString(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		return types.String(parsed.Name)
	default:
		return types.NewErrFromString("unsupported type for PURL name extraction")
	}
}

var version = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		parsed, err := packageurl.FromString(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		return types.String(parsed.Version)
	default:
		return types.NewErrFromString("unsupported type for PURL version extraction")
	}
}

var qualifiers = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		parsed, err := packageurl.FromString(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}

		// Convert qualifiers to map[string]string
		qualMap := make(map[string]string)
		for _, q := range parsed.Qualifiers {
			qualMap[q.Key] = q.Value
		}

		reg, err := types.NewRegistry()
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		return types.NewStringStringMap(reg, qualMap)
	default:
		return types.NewErrFromString("unsupported type for PURL qualifiers extraction")
	}
}

var subpath = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		parsed, err := packageurl.FromString(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		return types.String(parsed.Subpath)
	default:
		return types.NewErrFromString("unsupported type for PURL subpath extraction")
	}
}

func (pt *PurlTool) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case types.TypeType:
		return PurlType
	default:
		return types.NewErr("type conversion not allowed for purl")
	}
}

func (*PurlTool) Type() ref.Type {
	return PurlType
}

func (*PurlTool) Equal(other ref.Val) ref.Val {
	return types.NewErr("objects cannot be compared")
}

func (pt *PurlTool) Value() any {
	return pt
}

func (*PurlTool) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return nil, errors.New("purl cannot be converted to native")
}

type TypeAdapter struct{}

func (TypeAdapter) NativeToValue(value any) ref.Val {
	val, ok := value.(PurlTool)
	if ok {
		return &val
	}
	// let the default adapter handle other cases
	return types.DefaultTypeAdapter.NativeToValue(value)
}

// CompileOptions and ProgramOptions implement the cel.Library interface

func (pt *PurlTool) CompileOptions() []cel.EnvOption {
	funcs := pt.Functions()
	ret := make([]cel.EnvOption, 0, 3+len(funcs))
	ret = append(ret,
		cel.Types(PurlType),
		cel.CustomTypeAdapter(&TypeAdapter{}),
		cel.Variable("purl", PurlType),
	)
	ret = append(ret, funcs...)
	return ret
}

func (pt *PurlTool) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}
