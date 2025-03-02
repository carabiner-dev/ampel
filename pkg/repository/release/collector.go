// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"

	"github.com/carabiner-dev/ampel/pkg/attestation"
)

var _ attestation.Fetcher = (*Collector)(nil)

func New() (*Collector, error) {
	return &Collector{}, nil
}

// Init is the stub to initialize the collector with a new string
func (c *Collector) Init(string) error {
	return nil
}

type Options struct {
}

type Collector struct {
	Driver attestation.Fetcher
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return c.Driver.Fetch(ctx, opts)
}

func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	return c.Driver.FetchBySubject(ctx, opts, subj)
}

func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	return c.Driver.FetchByPredicateType(ctx, opts, pts)
}
