// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

type GitHubUtil struct{}

var GitHubType = cel.ObjectType("github", traits.ReceiverType)

func (ut *GitHubUtil) Functions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function(
			"parseRepo",
			cel.MemberOverload(
				"github_parse_repo",
				[]*cel.Type{GitHubType, cel.StringType}, cel.MapType(cel.StringType, cel.AnyType),
				cel.BinaryBinding(parseRepo),
			),
		),
		cel.Function(
			"orgDescriptorFromURI",
			cel.MemberOverload(
				"github_orgDescriptorFromURI",
				[]*cel.Type{GitHubType, cel.StringType}, cel.MapType(cel.StringType, cel.AnyType),
				cel.BinaryBinding(uriToOrgDescriptor),
			),
		),
		cel.Function(
			"repoDescriptorFromURI",
			cel.MemberOverload(
				"github_repoDescriptorFromURI",
				[]*cel.Type{GitHubType, cel.StringType}, cel.MapType(cel.StringType, cel.AnyType),
				cel.BinaryBinding(uriToRepoDescriptor),
			),
		),
	}
}

func parseRepoURI(uri string) (map[string]string, error) {
	if strings.HasPrefix(uri, "github.com/") {
		uri = "https://" + uri
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parsing uri string: %w", err)
	}

	path := strings.TrimPrefix(parsed.Path, "/")
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")

	// URL has no path
	if path == "" {
		return nil, errors.New("could not parse repository url")
	}

	// URL has no org/repo
	var repo = ""
	if len(parts) > 1 {
		repo = parts[1]
	}

	return map[string]string{
		"scheme": parsed.Scheme,
		"host":   parsed.Hostname(),
		"org":    parts[0],
		"repo":   repo,
	}, nil
}

var uriToRepoDescriptor = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		parts, err := parseRepoURI(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		if parts["repo"] == "" {
			return types.NewErrFromString("unable to create descriptor, no repo name defined in URL")
		}
		name := fmt.Sprintf("%s/%s/%s", parts["host"], parts["org"], parts["repo"])

		h := sha256.New()
		h.Write([]byte(name))
		digest := fmt.Sprintf("%x", h.Sum(nil))

		ret := map[string]any{
			"digest": map[string]string{
				"sha256": digest,
			},
			"name": name,
			"uri":  fmt.Sprintf("https://%s", name),
		}

		reg, err := types.NewRegistry()
		if err != nil {
			return types.NewErrFromString(err.Error())
		}

		return types.NewStringInterfaceMap(reg, ret)
	default:
		return types.NewErrFromString("unsupported type for repo parse")
	}
}

var uriToOrgDescriptor = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		parts, err := parseRepoURI(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		if parts["org"] == "" || parts["host"] == "" {
			return types.NewErrFromString("could not parse org from repo uri")
		}
		name := fmt.Sprintf("%s/%s", parts["host"], parts["org"])

		h := sha256.New()
		h.Write([]byte(name))
		digest := fmt.Sprintf("%x", h.Sum(nil))

		ret := map[string]any{
			"digest": map[string]string{
				"sha256": digest,
			},
			"name": name,
			"uri":  fmt.Sprintf("https://%s", name),
		}

		reg, err := types.NewRegistry()
		if err != nil {
			return types.NewErrFromString(err.Error())
		}

		return types.NewStringInterfaceMap(reg, ret)
	default:
		return types.NewErrFromString("unsupported type for repo parse")
	}
}

var parseRepo = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		parts, err := parseRepoURI(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}

		reg, err := types.NewRegistry()
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		return types.NewStringStringMap(reg, parts)

	default:
		return types.NewErrFromString("unsupported type for repo parse")
	}

}

func (ut *GitHubUtil) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case types.TypeType:
		return GitHubType

	default:
		return types.NewErr("type conversion not allowed for protobom")
	}
}

func (*GitHubUtil) Type() ref.Type {
	return GitHubType
}

func (*GitHubUtil) Equal(other ref.Val) ref.Val {
	return types.NewErr("objects cannot be compared")
}

func (ut *GitHubUtil) Value() any {
	return ut
}

func (*GitHubUtil) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return nil, errors.New("url cannot be converted to native")
}

type TypeAdapter struct{}

func (TypeAdapter) NativeToValue(value any) ref.Val {
	val, ok := value.(GitHubUtil)
	if ok {
		return &val
	} else {
		// let the default adapter handle other cases
		return types.DefaultTypeAdapter.NativeToValue(value)
	}
}

// CompileOptions and ProgramOptions implement the cel.Library interface

func (ut *GitHubUtil) CompileOptions() []cel.EnvOption {
	ret := []cel.EnvOption{
		cel.Types(GitHubType),
		cel.CustomTypeAdapter(&TypeAdapter{}),
		cel.Variable("github", GitHubType),
	}
	ret = append(ret, ut.Functions()...)
	return ret
}

func (ut *GitHubUtil) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}
