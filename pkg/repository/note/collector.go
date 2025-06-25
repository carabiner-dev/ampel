// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package note implements an attestation fetcher that can read from
// git commit notes.
package note

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/carabiner-dev/jsonl"
	"github.com/carabiner-dev/vcslocator"
	intoto "github.com/in-toto/attestation/go/v1"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/filters"
	"github.com/carabiner-dev/ampel/pkg/formats/envelope"
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

	return &Collector{
		Options: opts,
	}, nil
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

		ret = append(ret, envelopes...)
	}

	return ret, nil
}

// extractCommitBundle reads the jsonl attestations bundle from the commit
// notes data. Returns an error if cloning fails but nil if there is no
// bundle data in the commit.
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

	// We need two locators because we will check for sharded notes data
	// but also for direct files at the root of the notes reference. For
	// more details check this issue:
	//   https://github.com/slsa-framework/slsa-source-poc/issues/215
	uriShard := "git+" + components.RepoURL() + "@refs/notes/commits#" + path
	uriFile := "git+" + components.RepoURL() + "@refs/notes/commits#" + components.Commit

	// vcslocator 0.3.0 does not return a url for file urls, so we need to
	// build it manually:
	if components.Transport == vcslocator.TransportFile {
		uriShard = "file://" + components.RepoPath + "@refs/notes/commits#" + path
		uriFile = "file://" + components.RepoPath + "@refs/notes/commits#" + components.Commit
	}

	var bufferShard bytes.Buffer
	var bufferFile bytes.Buffer

	// OK, now copy the note data using the standard vcslocator functions.
	// We copy them as a group as the vcs locator module optimizes the cloning
	// ops. Note that this will always err, so we don't check the error immediately.
	err = vcslocator.CopyFileGroup(
		[]string{uriShard, uriFile}, []io.Writer{&bufferShard, &bufferFile},
	)

	// Depending on wether the notes data was sharded or not, one of the VCS
	// locators will contain the data and the other will err when opening the
	// non-existent file.
	switch {
	case bufferShard.Len() > 0:
		return &bufferShard, nil
	case bufferFile.Len() > 0:
		return &bufferFile, nil
	default:
		// Now, here we need to check. If the error is not found, then it means
		// there is no attestation data, not that there is an error
		err1, err2, _ := strings.Cut(err.Error(), "\n")
		if strings.Contains(err1, "file does not exist") &&
			strings.Contains(err2, "file does not exist") {
			return &bytes.Buffer{}, nil
		}
		return nil, err
	}
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
