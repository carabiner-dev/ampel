// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/carabiner-dev/vcslocator"
	"sigs.k8s.io/release-utils/http"
)

type PolicyFetcher interface {
	Get(string) ([]byte, error)
}

func NewFetcher() *Fetcher {
	return &Fetcher{}
}

type Fetcher struct{}

func (gf *Fetcher) Get(uri string) ([]byte, error) {
	switch {
	case strings.HasPrefix(uri, "http://"), strings.HasPrefix(uri, "https://"):
		return gf.GetFromHTTP(uri)
	case strings.HasPrefix(uri, "git+"):
		return gf.GetFromGit(uri)
	default:
		return nil, fmt.Errorf("unable to handle referenced URI")
	}
}

// GetFromHTTP retrieves data from an http endpoint
func (gf *Fetcher) GetFromHTTP(url string) ([]byte, error) {
	return http.NewAgent().Get(url)
}

// GetFromGit gets data from a git repository at the specified revision
func (gf *Fetcher) GetFromGit(locator string) ([]byte, error) {
	var b bytes.Buffer
	if err := vcslocator.CopyFile(locator, &b); err != nil {
		return nil, fmt.Errorf("fetching data from git: %w", err)
	}
	return b.Bytes(), nil
}
