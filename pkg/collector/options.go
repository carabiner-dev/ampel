// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import "github.com/carabiner-dev/ampel/pkg/attestation"

var defaultOptions = Options{
	UserAgentString: "ampel-collector/v1",
	ParallelFetches: 4,
	ParallelStores:  4,
	Fetch:           attestation.FetchOptions{},
	Store:           attestation.StoreOptions{},
}

// Options groups the configuration knob for the collector agent
type Options struct {
	UserAgentString string
	ParallelFetches int
	ParallelStores  int
	Fetch           attestation.FetchOptions
	Store           attestation.StoreOptions
}

// FetchOptionsFunc are functions to define options when fetching
type FetchOptionsFunc func(*attestation.FetchOptions)

// WithQuery passes a query to the options set
func WithQuery(q *attestation.Query) FetchOptionsFunc {
	return func(opts *attestation.FetchOptions) {
		opts.Query = q
	}
}

// StoreOptionsFunc are functions to define options when fetching
type StoreOptionsFunc func(*attestation.StoreOptions)
