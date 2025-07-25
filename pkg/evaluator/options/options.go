// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

// EvaluatorOptions are assembled by the verifier and passed deep to
// the evaluator when executing the policy tenets.
type EvaluatorOptions struct {
	LoadDefaultPlugins bool
}

var Default = EvaluatorOptions{
	LoadDefaultPlugins: true,
}

type OptFunc func(*EvaluatorOptions) error

func WithDefaultPlugins(sino bool) OptFunc {
	return func(eo *EvaluatorOptions) error {
		eo.LoadDefaultPlugins = sino
		return nil
	}
}
