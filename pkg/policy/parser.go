// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"os"

	v1 "github.com/carabiner-dev/ampel/pkg/api/v1"
	"sigs.k8s.io/release-utils/http"
)

const (
	AssertModeAND = "AND"
	AssertModeOR  = "OR"

	EnforceOn  = "ON"
	EnforceOff = "OFF"
)

func NewParser() *Parser {
	return &Parser{
		Fetcher: http.NewAgent(),
		impl:    &defaultParserImplementation{},
	}
}

type Parser struct {
	Fetcher PolicyFetcher
	impl    parserImplementation
}

// ParseFile parses a policy file
func (p *Parser) ParseFile(path string) (*v1.PolicySet, error) {
	// TODO(puerco): Support policies enclosed in envelopes
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading polciy file: %w", err)
	}

	return p.ParseSet(data)
}

type PolicyFetcher interface {
	Get(string) ([]byte, error)
}

// policyStore is a struct to hold the fetched remote policies
type policyStore map[string]fetchedRef

type fetchedRef struct {
	Data      *[]byte
	Policy    *v1.Policy
	PolicySet *v1.PolicySet
}

// ParseSet parses a policy set
func (p *Parser) ParseSet(policySetData []byte) (*v1.PolicySet, error) {
	// Parse the policy set data
	set, err := p.impl.ParsePolicySet(policySetData)
	if err != nil {
		return nil, fmt.Errorf("parsing policy source: %w", err)
	}

	// Fetch the remote policies referenced in the set to complete it
	store, err := p.impl.FetchReferences(p.Fetcher, set)
	if err != nil {
		return nil, fmt.Errorf("fetching remote references: %w", err)
	}

	// Complete the PolicySet
	if err := p.impl.CompletePolicySet(set, store); err != nil {
		return nil, fmt.Errorf("completing policy set: %s", err)
	}

	return set, nil
}
