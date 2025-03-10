// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	api "github.com/carabiner-dev/ampel/pkg/api/v1"
)

type EvaluatorOptions struct {
	Context            *api.Context
	LoadDefaultPlugins bool
}

var Default = EvaluatorOptions{
	Context:            nil,
	LoadDefaultPlugins: true,
}

type OptFunc func(*EvaluatorOptions) error

func WithDefaultPlugins(sino bool) OptFunc {
	return func(eo *EvaluatorOptions) error {
		eo.LoadDefaultPlugins = sino
		return nil
	}
}

func WithContext(c *api.Context) OptFunc {
	return func(eo *EvaluatorOptions) error {
		eo.Context = c
		return nil
	}
}
