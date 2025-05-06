// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"context"
	"errors"
)

var (
	ErrFetcherMethodNotImplemented = errors.New("fetching method not implemented")
	ErrStorerMethodNotImplemented  = errors.New("storing method not implemented")
)

type Repository interface{} //nolint:iface // To be implemented

// AttestationFetcher is the the trait that repositories that can fetch
// attestations must implement
type Fetcher interface {
	Fetch(context.Context, FetchOptions) ([]Envelope, error)
	FetchBySubject(context.Context, FetchOptions, []Subject) ([]Envelope, error)
	FetchByPredicateType(context.Context, FetchOptions, []PredicateType) ([]Envelope, error)
}

type Storer interface {
	Store(context.Context, StoreOptions, []Envelope) error
}

// StoreOptions control how attestations are retrieved from a Fetcher. All
// repositories implementing the Fetcher interface are expected to honor FetchOptions.
type FetchOptions struct {
	Limit int
	Query *Query
}

// StoreOptions control how attestations are stored in the storer. All repositories
// implementing the Storer interface are expected to honor StoreOptions.
type StoreOptions struct{}
