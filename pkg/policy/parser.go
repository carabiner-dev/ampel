// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/carabiner-dev/vcslocator"
	"sigs.k8s.io/release-utils/http"

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

// Open opens a Policy or policySet. This function supports remote locations
// (https URLs or VCS locators) and will eventually verify signatures after
// reading and parsing data (still under construction).
func (p *Parser) Open(location string) (set *api.PolicySet, pcy *api.Policy, err error) {
	compiler, err := NewCompiler()
	if err != nil {
		return nil, nil, fmt.Errorf("creating policy compiler: %w", err)
	}

	// Open de PolicySet/Policy data from files or remote locations
	var data []byte
	switch {
	case strings.HasPrefix(location, "git+https://"), strings.HasPrefix(location, "git+ssh://"):
		var b bytes.Buffer
		if err := vcslocator.CopyFile(location, &b); err != nil {
			return nil, nil, fmt.Errorf("copying data from repository: %w", err)
		}
		data = b.Bytes()
	case strings.HasPrefix(location, "https://"):
		data, err = http.NewAgent().Get(location)
	default:
		data, err = os.ReadFile(location)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("opening policy data: %w", err)
	}

	// Parse the read data
	set, pcy, err = p.ParsePolicyOrSet(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing policy data: %w", err)
	}

	// Compile the PolicySet/Policy
	if set != nil {
		set, err = compiler.CompileSet(set)
		if err != nil {
			return nil, nil, fmt.Errorf("compiling policy set: %w", err)
		}
		return set, nil, nil
	} else {
		pcy, err = compiler.CompilePolicy(pcy)
		if err != nil {
			return nil, nil, fmt.Errorf("compiling policy: %w", err)
		}
		return nil, pcy, nil
	}
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
		pcy, errPolicy = p.impl.ParsePolicy(data)
	}()

	// Wait for both parsers
	wg.Wait()

	if (set == nil && pcy == nil) || (errSet != nil && errPolicy != nil) {
		return nil, nil, errors.New("unable to parse a policy or policySet from data")
	}
	return set, pcy, nil
}
