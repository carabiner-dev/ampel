// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Pacakge jsonl implements an attestations collector that reads
// from files using the JSON Lines (jsonl) format.
package jsonl

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/envelope"
	"github.com/nozzle/throttler"
)

func New(funcs ...optFn) (*Collector, error) {
	// Apply the functional options
	opts := Options{}
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
	Options Options
}

// readAttestations
func (c *Collector) readAttestations(paths []string, filters *attestation.FilterSet) ([]attestation.Envelope, error) {
	t := throttler.New(c.Options.MaxParallel, len(paths))
	ret := []attestation.Envelope{}
	var mtx = sync.Mutex{}
	for _, path := range paths {
		path := path
		go func() {
			moreAtts, err := parseFile(path, filters)
			if err != nil {
				t.Done(err)
				return
			}
			mtx.Lock()
			ret = append(ret, moreAtts...)
			mtx.Unlock()
			t.Done(nil)
		}()
		t.Throttle()
	}
	if err := t.Err(); err != nil {
		return nil, err
	}
	return ret, nil
}

func parseFile(path string, filters *attestation.FilterSet) ([]attestation.Envelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", path, err)
	}
	ret := []attestation.Envelope{}
	scanner := bufio.NewScanner(f)
	i := 0
	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		reader := strings.NewReader(scanner.Text())
		envelope, err := envelope.Parsers.Parse(reader)
		if err != nil {
			return nil, fmt.Errorf("parsing attestation %d in %q: %w", i, path, err)
		}
		ret = append(ret, envelope...)
		i++
	}
	return ret, nil
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return nil, attestation.ErrFetcherMethodNotImplemented
}

func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	return nil, attestation.ErrFetcherMethodNotImplemented
}

func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	return nil, attestation.ErrFetcherMethodNotImplemented
}
