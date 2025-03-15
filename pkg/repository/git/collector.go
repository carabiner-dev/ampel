// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Pacakge git implements an attestations collector that works on a git repository.
// This package implements the logic to interact with the git repo and relies on
// the filesystem collector to fetch and classify attestations.
package git

import (
	"context"
	"fmt"

	"github.com/go-git/go-billy/v5/helper/iofs"
	"github.com/go-git/go-billy/v5/memfs"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/repository/filesystem"
)

var TypeMoniker = "git"

// Implement the factory function
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithPath(istr))
}

var _ attestation.Fetcher = (*Collector)(nil)

func New(funcs ...optFn) (*Collector, error) {
	// Apply the functional options
	opts := defaultOptions
	for _, fn := range funcs {
		fn(&opts)
	}

	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}

	return &Collector{
		Options: opts,
	}, nil
}

type Collector struct {
	Repo        *git.Repository
	FSCollector *filesystem.Collector
	Options     Options
}

// clone clones the repository and sets up the filesystem and fs collector
func (c *Collector) clone() error {
	// For now we clone the data to memory, this could
	// be an option
	fs := memfs.New()

	// Make a shallow clone of the repo to memory
	r, err := git.Clone(memory.NewStorage(), fs, &git.CloneOptions{
		URL: c.Options.URL,
		// Progress:      os.Stdout,
		ReferenceName: plumbing.ReferenceName(c.Options.Ref),
		SingleBranch:  true,
		Depth:         1,
		// RecurseSubmodules: 0,
		// ShallowSubmodules: false,
	})
	if err != nil {
		return fmt.Errorf("cloning repo: %w", err)
	}
	c.Repo = r

	fscollector, err := filesystem.New(
		filesystem.WithFS(iofs.New(fs)),
		filesystem.WithPath(c.Options.Path),
	)
	if err != nil {
		return fmt.Errorf("creating new fs collector: %w", err)
	}
	c.FSCollector = fscollector
	return nil
}

func (c *Collector) ensureClone() error {
	if c.FSCollector == nil {
		return c.clone()
	}
	return nil
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	if err := c.ensureClone(); err != nil {
		return nil, err
	}
	return c.FSCollector.Fetch(ctx, opts)
}

// FetchBySubject calls the attestation reader with a filter preconfigured
// with subject hashes.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	if err := c.ensureClone(); err != nil {
		return nil, err
	}
	return c.FSCollector.FetchBySubject(ctx, opts, subj)
}

func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	if err := c.ensureClone(); err != nil {
		return nil, err
	}
	return c.FSCollector.FetchByPredicateType(ctx, opts, pts)
}
