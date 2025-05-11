// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"
	"os"
	"sync"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
)

const (
	AssertModeAND = "AND"
	AssertModeOR  = "OR"

	EnforceOn  = "ON"
	EnforceOff = "OFF"
)

var ErrUnsupportedLocationURI = errors.New("unsupported policy location")

// NewParser creates a new policy parser
func NewParser() *Parser {
	return &Parser{
		impl: &defaultParserImplementationV1{},
	}
}

// Parser implements methods to read the policy and policy set json files.
// Note that the parser only deals with decoding json. Use the policy compiler
// to assemble policies with external/remote references.
type Parser struct {
	impl parserImplementation
}

// ParseFile parses a policySet from a file
func (p *Parser) ParsePolicySetFile(path string) (*api.PolicySet, error) {
	// TODO(puerco): Support policies enclosed in envelopes
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading polciy file: %w", err)
	}

	return p.ParsePolicySet(data)
}

// ParsePolicyFile parses a policy from a file
func (p *Parser) ParsePolicyFile(path string) (*api.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading polciy file: %w", err)
	}

	return p.ParsePolicy(data)
}

// ParseSet parses a policy set.
func (p *Parser) ParsePolicySet(policySetData []byte) (*api.PolicySet, error) {
	// Parse the policy set data
	set, err := p.impl.ParsePolicySet(policySetData)
	if err != nil {
		return nil, fmt.Errorf("parsing policy source: %w", err)
	}
	return set, nil
}

// ParsePolicy parses a policy file
func (p *Parser) ParsePolicy(data []byte) (*api.Policy, error) {
	pcy, err := p.impl.ParsePolicy(data)
	if err != nil {
		return nil, fmt.Errorf("parsing policy data: %w", err)
	}
	return pcy, nil
}

// ParsePolicyOrSet takes json data and tries to parse a policy or a policy set
// out of it. Returns an error if the JSON data is none.
func (p *Parser) ParsePolicyOrSet(data []byte) (set *api.PolicySet, pcy *api.Policy, err error) {
	var wg sync.WaitGroup
	wg.Add(2)

	var errSet, errPolicy error
	go func() {
		defer wg.Done()
		set, errSet = p.impl.ParsePolicySet(data)
	}()
	go func() {
		defer wg.Done()
		set, errPolicy = p.impl.ParsePolicySet(data)
	}()

	if errSet != nil && errPolicy != nil {
		return nil, nil, errors.New("unable to parse a policy or policySet from data")
	}
	return set, pcy, nil
}
