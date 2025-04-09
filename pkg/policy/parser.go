// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"os"

	v1 "github.com/carabiner-dev/ampel/pkg/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	AssertModeAND = "AND"
	AssertModeOR  = "OR"

	EnforceOn  = "ON"
	EnforceOff = "OFF"
)

func NewParser() *Parser {
	return &Parser{}
}

type Parser struct{}

// ParseFile parses a policy file
func (p *Parser) ParseFile(path string) (*v1.PolicySet, error) {
	// TODO(puerco): Support policies enclosed in envelopes
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading polciy file: %w", err)
	}

	return p.ParseSet(data)
}

func (p *Parser) ParseSet(policySetData []byte) (*v1.PolicySet, error) {
	set := v1.PolicySet{}
	// dec := json.NewDecoder(bytes.NewReader(policySetData))

	if err := protojson.Unmarshal(policySetData, &set); err != nil {
		return nil, fmt.Errorf("parsing policy source: %w", err)
	}

	for _, p := range set.Policies {
		// TODO(puerco): Verify if policy source is enabled in addition to
		// policy data. it shoud probably be a Verify function in the policy
		if p.Source != nil {
			// TODO(puerco): Fetch the externally referenced policy here.
		}

		if p.GetMeta().GetAssertMode() == "" {
			p.GetMeta().AssertMode = AssertModeAND
		}

		if p.GetMeta().GetEnforce() == "" {
			p.GetMeta().Enforce = EnforceOn
		}
	}
	return &set, nil
}
