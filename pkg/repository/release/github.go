// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/github"
)

// GitHub is a release driver for GitHub releases
type GitHub struct {
	client github.Client
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *GitHub) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return nil, attestation.ErrFetcherMethodNotImplemented
}

func (c *GitHub) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	return nil, attestation.ErrFetcherMethodNotImplemented
}

func (c *GitHub) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	return nil, attestation.ErrFetcherMethodNotImplemented
}
