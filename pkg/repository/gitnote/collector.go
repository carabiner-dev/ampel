// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package gitnote implementes an attestation fetcher that can read from
// git commit notes.
package gitnote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/carabiner-dev/jsonl"
	intoto "github.com/in-toto/attestation/go/v1"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/filters"
	"github.com/carabiner-dev/ampel/pkg/formats/envelope"
	"github.com/carabiner-dev/vcslocator"
)

var TypeMoniker = "note"

// Implement the factory function
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithLocator(istr))
}

var _ attestation.Fetcher = (*Collector)(nil)

type Collector struct {
	Options Options
}

func New(funcs ...optFn) (*Collector, error) {
	// Apply the functional options
	opts := defaultOptions
	for _, fn := range funcs {
		fn(&opts)
	}

	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}

	return &Collector{}, nil
}

type Options struct {
	Locator string
}

var defaultOptions Options

type optFn = func(*Options)

func WithLocator(locator string) optFn {
	return func(opts *Options) {
		opts.Locator = locator
	}
}

func (o *Options) Validate() error {
	return nil
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	ret := []attestation.Envelope{}

	reader, err := c.extractCommitBundle()
	if err != nil {
		return nil, err
	}

	for i, r := range jsonl.IterateBundle(reader) {
		if r == nil {
			continue
		}

		// Parse the JSON doc
		envelopes, err := envelope.Parsers.Parse(r)
		if err != nil {
			return nil, fmt.Errorf("parsing attestation %d in %q: %w", i, c.Options.Locator, err)
		}

		// If the json did not return anything (not likely)
		if len(envelopes) == 0 {
			continue
		}

		// Complete the attestation source, we know that the envelope returns max 1
		// attestation per line
		if envelopes[0].GetStatement() != nil &&
			envelopes[0].GetStatement().GetPredicate() != nil &&
			envelopes[0].GetStatement().GetPredicate().GetSource() != nil {
			rd := &intoto.ResourceDescriptor{
				Name:   fmt.Sprintf("jsonl:%s#%d", c.Options.Locator, i),
				Uri:    fmt.Sprintf("jsonl:%s#%d", c.Options.Locator, i),
				Digest: envelopes[0].GetStatement().GetPredicate().GetSource().GetDigest(),
			}
			envelopes[0].GetStatement().GetPredicate().SetSource(rd)
		}
	}

	return ret, nil
}

func (c *Collector) extractCommitBundle() (io.Reader, error) {
	if c.Options.Locator == "" {
		return nil, errors.New("unable to read note, no VCS locator set")
	}

	components, err := vcslocator.Locator(c.Options.Locator).Parse()
	if err != nil {
		return nil, fmt.Errorf("parsing VCS locator: %w", err)
	}

	if components.Commit == "" {
		return nil, fmt.Errorf("VCS locator must specify a commit sha")
	}

	path := components.Commit[0:2] + "/" + components.Commit[2:]

	// Now, reform the repo URL to fetch the notes
	var b bytes.Buffer

	// For remote URIs, construct the note VCS locator using the repoURL:
	uri := "git+" + components.RepoURL() + "@refs/notes/commits#" + path

	// vcslocator 0.3.0 does not return a url for file urls, so we need to
	// build it manually:
	if components.Transport == vcslocator.TransportFile {
		uri = "file://" + components.RepoPath + "@refs/notes/commits#" + path
	}

	// OK, now copy the note data using the standard vcslocator funcs:
	if err := vcslocator.CopyFile(
		vcslocator.Locator(uri), &b,
	); err != nil {
		return nil, fmt.Errorf("fetching git note: %w", err)
	}

	return &b, nil
}

// FetchBySubject calls the attestation reader with a filter preconfigured
// with subject hashes.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	all, err := c.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}

	matcher := &filters.SubjectHashMatcher{
		HashSets: []map[string]string{},
	}

	for _, s := range subj {
		matcher.HashSets = append(matcher.HashSets, s.GetDigest())
	}

	return attestation.NewQuery().WithFilter(matcher).Run(all), nil
}

func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	all, err := c.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}

	matcher := &filters.PredicateTypeMatcher{
		PredicateTypes: map[attestation.PredicateType]struct{}{},
	}

	for _, pt := range pts {
		matcher.PredicateTypes[pt] = struct{}{}
	}

	return attestation.NewQuery().WithFilter(matcher).Run(all), nil
}
