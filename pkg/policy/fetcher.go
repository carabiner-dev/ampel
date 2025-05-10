// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"

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

// GetGroup fetches a list of uris that can be HTTP(S) URLs or SPDX VCS locators.
// The functions uses the vcslocator module and the k8s http agent to fetch in
// parallel. The returned slice if byte-slices is guarranteed to preserve the
// URL order. If a request fails, this function returns a single error and discards
// all data.
//
// Retries are currently not supported but will probably be at a later point once
// the VCS locator module supports retrying.
func (gf *Fetcher) GetGroup(uris []string) ([][]byte, error) {
	// Split the URIs into http and vcs locators
	locators := map[int]string{}
	urls := map[int]string{}
	for i, uri := range uris {
		switch {
		case strings.HasPrefix(uri, "http://"), strings.HasPrefix(uri, "https://"):
			urls[i] = uri
		case strings.HasPrefix(uri, "git+"):
			locators[i] = uri
		default:
			return nil, fmt.Errorf("unable to handle referenced URI %q", uri)
		}
	}

	var locatorErr error

	// Prealocate the return slice to populate later
	ret := make([][]byte, len(uris))
	errs := []error{}
	var mtx sync.Mutex
	// Create a waitgroup to fetch in parallel:
	var wg sync.WaitGroup
	wg.Add(2)

	// Fetch the VCS locators
	go func() {
		defer wg.Done()
		if len(locators) == 0 {
			return
		}
		uris := make([]string, len(locators))
		order := map[int]int{}
		i := 0
		for k, l := range locators {
			order[i] = k
			uris[i] = l
			i++
		}

		var res [][]byte
		res, locatorErr = vcslocator.GetGroup(uris)

		// If error, return early
		if locatorErr != nil {
			return
		}

		mtx.Lock()
		for i, data := range res {
			ret[order[i]] = data
		}
		mtx.Unlock()
	}()

	// Fetch the HTTP references
	go func() {
		defer wg.Done()
		if len(urls) == 0 {
			return
		}

		uris := make([]string, len(urls))
		order := map[int]int{}
		i := 0
		for k, l := range urls {
			order[i] = k
			uris[i] = l
			i++
		}

		var res [][]byte
		res, errs = http.NewAgent().GetGroup(uris)
		if errors.Join(errs...) != nil {
			return
		}

		mtx.Lock()
		for i, data := range res {
			ret[order[i]] = data
		}
		mtx.Unlock()
	}()

	// Waint until both are done
	wg.Wait()

	// Now, merge the results of both operations.
	// First the errors. The vcs locator module returns a single error
	// while the http error returns a slice, so we combine them before join.
	if locatorErr != nil {
		errs = append(errs, locatorErr)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return ret, nil
}

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
