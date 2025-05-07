// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/carabiner-dev/vcslocator"
	"sigs.k8s.io/release-utils/http"
	"sigs.k8s.io/release-utils/util"

	v1 "github.com/carabiner-dev/ampel/pkg/api/v1"
)

const (
	AssertModeAND = "AND"
	AssertModeOR  = "OR"

	EnforceOn  = "ON"
	EnforceOff = "OFF"
)

var ErrUnsupportedLocationURI = errors.New("unsupported policy location")

func NewParser() *Parser {
	return &Parser{
		Fetcher: NewFetcher(),
		impl:    &defaultParserImplementation{},
	}
}

type Parser struct {
	Fetcher PolicyFetcher
	impl    parserImplementation
}

// OpenPolicySet opens a policy set file from a file or a remote location (git/https)
func (p *Parser) OpenPolicySet(pathUri string) (*v1.PolicySet, error) {
	// First, try a local file:
	if util.Exists(pathUri) {
		return p.ParseFile(pathUri)
	}
	// if its not a file, open it from a remote location:
	return p.OpenRemotePolicySet(pathUri)
}

// OpenRemoteSet opens a policy set from a remote location
func (p *Parser) OpenRemotePolicySet(uri string) (*v1.PolicySet, error) {
	// Check the string, at this point we know it is not a local file
	if strings.Contains(uri, "git+https:") || strings.Contains(uri, "git+ssh:") {
		var b bytes.Buffer
		if err := vcslocator.CopyFile(uri, &b); err != nil {
			return nil, fmt.Errorf("opening policy from git: %w", err)
		}
		return p.ParseSet(b.Bytes())
	}

	// Next, try to se if its a URL
	u, err := url.Parse(uri)
	// If we could not parse it, then we're done
	if err != nil {
		return nil, ErrUnsupportedLocationURI
	}

	// We only support https policies for now
	if u.Scheme != "https" {
		return nil, ErrUnsupportedLocationURI
	}

	// Fetch the data
	data, err := http.NewAgent().Get(uri)
	if err != nil {
		return nil, fmt.Errorf("HTTP error opening remote policy: %w", err)
	}

	return p.ParseSet(data)
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
		return nil, fmt.Errorf("completing policy set: %w", err)
	}

	return set, nil
}
