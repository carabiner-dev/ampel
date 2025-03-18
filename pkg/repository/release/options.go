// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"errors"

	"github.com/carabiner-dev/github"
)

var defaultOptions = Options{}

type optFn = func(*Collector) error

type Options struct {
	RepoURL string
	Tag     string
}

func WithRepo(repo string) optFn {
	return func(c *Collector) error {
		url, err := github.RepoFromString(repo)
		if err != nil {
			return err
		}
		c.Options.RepoURL = url
		return nil
	}
}

func WithTag(tag string) optFn {
	return func(c *Collector) error {
		c.Options.Tag = tag
		return nil
	}
}

func (o *Options) Validate() error {
	errs := []error{}
	if o.RepoURL == "" {
		errs = append(errs, errors.New("no repository URL set"))
	}
	return errors.Join(errs...)
}
