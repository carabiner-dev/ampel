// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package jsonl

import (
	"errors"
	"fmt"
	"slices"

	"sigs.k8s.io/release-utils/util"
)

type Options struct {
	MaxParallel int
	Paths       []string
}

func (o *Options) Validate() error {
	errs := []error{}
	for _, p := range o.Paths {
		if !util.Exists(p) {
			errs = append(errs, fmt.Errorf("file not found: %q", p))
		}
	}
	return errors.Join(errs...)
}

type optFn = func(*Options)

func WithPath(path string) optFn {
	return func(opts *Options) {
		if !slices.Contains(opts.Paths, path) {
			opts.Paths = append(opts.Paths, path)
		}
	}
}

func WithMaxParallel(w int) optFn {
	return func(opts *Options) {
		opts.MaxParallel = w
	}
}
