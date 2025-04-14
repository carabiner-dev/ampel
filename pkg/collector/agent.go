// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/nozzle/throttler"
	"github.com/sirupsen/logrus"

	"github.com/carabiner-dev/ampel/pkg/attestation"
)

var (
	ErrNoFetcherConfigured = errors.New("no repository with fetch capabilities configured")
	ErrNoStorerConfigured  = errors.New("no repository with store capabilities configured")
)

// New returns a new agent with the default options
func New(funcs ...InitFunction) (*Agent, error) {
	agent := NewWithOptions(&defaultOptions)
	for _, fn := range funcs {
		if err := fn(agent); err != nil {
			return nil, err
		}
	}
	return agent, nil
}

// NewWithOptions returns a new agent configured with a specific options set
func NewWithOptions(opts *Options) *Agent {
	return &Agent{
		Options:      *opts,
		Repositories: []attestation.Repository{},
	}
}

// Agent is the attestations collector agent. The agent registers a number
// of repositories and can look for attestations in them.
//
// The agent exposes the attestation.Fetcher and attestation.Storer methods,
// when called, the collector agent invokes the corresponding method in all
// configured repository drivers.
type Agent struct {
	Options      Options
	Repositories []attestation.Repository
}

func (agent *Agent) AddRepositoryFromString(init string) error {
	repo, err := RepositoryFromString(init)
	if err != nil {
		return fmt.Errorf("building repo: %w", err)
	}
	agent.Repositories = append(agent.Repositories, repo)
	return nil
}

// AddRepsitory adds a new repository to collect attestations
func (agent *Agent) AddRepository(repos ...attestation.Repository) error {
	agent.Repositories = append(agent.Repositories, repos...)
	return nil
}

// Fetch is a general attestation fetcher. It is intended to return attestations
// in the preferred order of the driver without any optimization whatsoever.
func (agent *Agent) Fetch(ctx context.Context, optFn ...FetchOptionsFunc) ([]attestation.Envelope, error) {
	mutex := sync.Mutex{}
	ret := []attestation.Envelope{}

	// Filter the repos to get the fetchers
	repos := agent.fetcherRepos()
	if len(repos) == 0 {
		return nil, ErrNoFetcherConfigured
	}

	opts := agent.Options.Fetch
	if len(optFn) > 0 {
		return nil, fmt.Errorf("functional options not yet implemented")
	}

	t := throttler.New((agent.Options.ParallelFetches), len(repos))

	for _, r := range repos {
		r := r
		go func() {
			// Call the repo driver's fetch method
			atts, err := r.Fetch(ctx, opts)
			if err != nil {
				t.Done(err)
				return
			}

			mutex.Lock()
			ret = append(ret, atts...)
			mutex.Unlock()
			t.Done(nil)
		}()
		t.Throttle()
	}

	return ret, t.Err()
}

// FetchAttestationsBySubject requests all attestations about a list of subjects
// from the configured repositories. It is understood that the repos will return
// all attestations available about the specified subjects.
func (agent *Agent) FetchAttestationsBySubject(ctx context.Context, subjects []attestation.Subject, optFn ...FetchOptionsFunc) ([]attestation.Envelope, error) {
	mutex := sync.Mutex{}
	ret := []attestation.Envelope{}

	// Filter the repos to get the fetchers
	repos := agent.fetcherRepos()
	if len(repos) == 0 {
		if agent.Options.FailIfNoFetchers {
			return nil, ErrNoFetcherConfigured
		}
		logrus.Debugf("WARN: No fetcher repos configured")
		return ret, nil
	}

	opts := agent.Options.Fetch
	for _, f := range optFn {
		f(&opts)
	}

	t := throttler.New((agent.Options.ParallelFetches), len(repos))

	for _, r := range repos {
		r := r
		go func() {
			atts, err := r.FetchBySubject(ctx, opts, subjects)
			if err != nil {
				t.Done(err)
				return
			}

			mutex.Lock()
			ret = append(ret, atts...)
			mutex.Unlock()
			t.Done(nil)
		}()
		t.Throttle()
	}

	if opts.Query != nil {
		ret = opts.Query.Run(ret)
	}

	// Limit the returnes attestations. Mmmh....
	if opts.Limit != 0 {
		ret = ret[0:opts.Limit]
	}

	return ret, t.Err()
}

// FetchAttestationsByPredicateType requests all attestations of a particular type
// from the configured repositories.
func (agent *Agent) FetchAttestationsByPredicateType(ctx context.Context, pt []attestation.PredicateType, optFn ...FetchOptionsFunc) ([]attestation.Envelope, error) {
	mutex := sync.Mutex{}
	ret := []attestation.Envelope{}

	// Filter the repos to get the fetchers
	repos := agent.fetcherRepos()
	if len(repos) == 0 {
		return nil, ErrNoFetcherConfigured
	}

	opts := agent.Options.Fetch
	for _, f := range optFn {
		f(&opts)
	}

	t := throttler.New((agent.Options.ParallelFetches), len(repos))

	for _, r := range repos {
		r := r
		go func() {
			// Call the repo driver's fetch method
			atts, err := r.FetchByPredicateType(ctx, opts, pt)
			if err != nil {
				t.Done(err)
				return
			}

			mutex.Lock()
			ret = append(ret, atts...)
			mutex.Unlock()
			t.Done(nil)
		}()
		t.Throttle()
	}

	if opts.Query != nil {
		ret = opts.Query.Run(ret)
	}

	// Limit the returnes attestations. Mmmh....
	if opts.Limit != 0 {
		ret = ret[0:opts.Limit]
	}

	return ret, t.Err()
}
