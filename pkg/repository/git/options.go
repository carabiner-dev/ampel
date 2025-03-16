// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Pacakge jsonl implements an attestations collector that reads
// from files using the JSON Lines (jsonl) format.

package git

import (
	"fmt"
	"net/url"
	"strings"
)

type optFn = func(*Options) error

type Options struct {
	URL    string
	Path   string
	Ref    string
	Commit string
}

var defaultOptions = Options{}

func (o *Options) Validate() error {
	return nil
}

func WithLocator(init string) optFn {
	return func(opts *Options) error {
		u, err := url.Parse(init)
		if err != nil {
			return fmt.Errorf("parsing url: %w", err)
		}
		path, branch, ok := strings.Cut(u.Path, "@")
		sch := u.Scheme
		if sch != "" {
			sch += "://"
		}
		opts.URL = sch + u.Hostname() + path
		if ok {
			opts.Ref = branch
		}
		opts.Path = u.Fragment
		return nil
	}
}

func WithPath(path string) optFn {
	return func(opts *Options) error {
		opts.Path = path
		return nil
	}
}
