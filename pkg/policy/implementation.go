// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/carabiner-dev/ampel/pkg/api/v1"
)

type parserImplementation interface {
	ParsePolicySet([]byte) (*v1.PolicySet, error)
	ParsePolicy([]byte) (*v1.Policy, error)
}

type defaultParserImplementationV1 struct{}

func (dpi *defaultParserImplementationV1) ParsePolicySet(policySetData []byte) (*v1.PolicySet, error) {
	set := &v1.PolicySet{}
	err := protojson.UnmarshalOptions{
		AllowPartial:   false,
		DiscardUnknown: false,
	}.Unmarshal(policySetData, set)
	if err != nil {
		return nil, fmt.Errorf("parsing policy set source: %w", err)
	}

	if set.GetMeta() == nil {
		set.Meta = &v1.PolicySetMeta{}
	}

	if set.GetMeta().GetEnforce() == "" {
		set.GetMeta().Enforce = EnforceOn
	}

	for _, p := range set.Policies {
		if p.GetMeta() == nil {
			p.Meta = &v1.Meta{}
		}

		if p.GetMeta().GetAssertMode() == "" {
			p.GetMeta().AssertMode = AssertModeAND
		}

		if p.GetMeta().GetEnforce() == "" {
			p.GetMeta().Enforce = EnforceOn
		}
	}
	return set, nil
}

func (dpi *defaultParserImplementationV1) ParsePolicy(policySetData []byte) (*v1.Policy, error) {
	p := &v1.Policy{}
	err := protojson.UnmarshalOptions{
		AllowPartial:   false,
		DiscardUnknown: false,
	}.Unmarshal(policySetData, p)
	if err != nil {
		return nil, fmt.Errorf("parsing policy source: %w", err)
	}

	if p.GetMeta() == nil {
		p.Meta = &v1.Meta{}
	}

	if p.GetMeta().GetEnforce() == "" {
		p.GetMeta().Enforce = EnforceOn
	}

	if p.GetMeta().GetAssertMode() == "" {
		p.GetMeta().AssertMode = AssertModeAND
	}

	return p, nil
}
