// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package filesystem implements an attestation collector from a fs.FS
package filesystem

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/filters"
	"github.com/carabiner-dev/ampel/pkg/formats/envelope"
)

var TypeMoniker = "fs"

// Implement the factory function
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithInitString(istr))
}

func New(opts ...fnOpts) (*Collector, error) {
	c := &Collector{
		Extensions:       []string{"json", "jsonl", "spdx", "cdx", "bundle"},
		IgnoreOtherFiles: true,
		Path:             ".",
	}
	for _, f := range opts {
		if err := f(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

type fnOpts func(*Collector) error

var WithInitString = func(s string) fnOpts {
	return func(c *Collector) error {
		c.FS = os.DirFS(s)
		return nil
	}
}

var WithFS = func(iofs fs.FS) fnOpts {
	return func(c *Collector) error {
		c.FS = iofs
		return nil
	}
}

var WithPath = func(path string) fnOpts {
	return func(c *Collector) error {
		c.Path = strings.TrimPrefix(path, "/")
		if c.Path == "" {
			c.Path = "."
		}
		return nil
	}
}

var _ attestation.Fetcher = (*Collector)(nil)

// Collector is the filesystem collector
type Collector struct {
	Extensions       []string
	IgnoreOtherFiles bool
	Path             string
	FS               fs.FS
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	if c.FS == nil {
		return nil, errors.New("collector has no filesystem defined")
	}

	ret := []attestation.Envelope{}

	// Walk the filesystem and read any attestations
	if err := fs.WalkDir(c.FS, c.Path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("scanning at %s: %w", path, err)
		}

		if d.IsDir() {
			return nil
		}

		if c.IgnoreOtherFiles {
			ext := filepath.Ext(path)
			if !slices.Contains(c.Extensions, strings.TrimPrefix(ext, ".")) {
				return nil
			}
		}

		// Read the file data from the filesystem
		bs, err := fs.ReadFile(c.FS, path)
		if err != nil {
			return fmt.Errorf("reading file from fs: %w", err)
		}

		// Pass the read data to all the enabled parsers
		attestations, err := envelope.Parsers.Parse(bytes.NewReader(bs))
		if err != nil {
			return fmt.Errorf("parsing file: %w", err)
		}

		if opts.Query != nil {
			attestations = opts.Query.Run(attestations)
		}
		ret = append(ret, attestations...)

		return nil
	}); err != nil {
		return nil, fmt.Errorf("scanning filesystem at %s: %w", c.Path, err)
	}
	return ret, nil
}

func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	return nil, attestation.ErrFetcherMethodNotImplemented
}
func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	filter := filters.PredicateTypeMatcher{
		PredicateTypes: map[attestation.PredicateType]struct{}{},
	}

	for _, pt := range pts {
		filter.PredicateTypes[pt] = struct{}{}
	}

	if opts.Query == nil {
		opts.Query = &attestation.Query{
			Filters: []attestation.Filter{&filter},
		}
	} else {
		opts.Query.Filters = append(opts.Query.Filters, &filter)
	}

	return c.Fetch(ctx, opts)
}
