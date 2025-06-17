// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"os"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
)

type CompilerOptions struct {
	// TODO: No remote data
	// TODO: Fail merging on unknown remote tenet ids

	// MaxRemoteRecursion captures the maximum recursion level the
	// compiler will do to fetch remote content. Note that this setting
	// causes exponential requests, so be careful when defining a value.
	MaxRemoteRecursion int
}

var defaultCompilerOpts = CompilerOptions{
	MaxRemoteRecursion: 3,
}

// Compiler is the policy compiler
type Compiler struct {
	Options CompilerOptions
	Store   StorageBackend
	impl    compilerImplementation
}

func NewCompiler() (*Compiler, error) {
	opts := defaultCompilerOpts
	return &Compiler{
		Options: opts,
		Store:   newRefStore(),
		impl:    &defaultCompilerImpl{},
	}, nil
}

func (compiler *Compiler) CompileFile(path string) (set *api.PolicySet, pcy *api.Policy, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading policy file: %w", err)
	}
	return compiler.Compile(data)
}

// Compile is main method to assemble policies.
//
// Compiling means fetching all the policy references and assembling a
// policy in memory with the fetched data.
func (compiler *Compiler) Compile(data []byte) (set *api.PolicySet, pcy *api.Policy, err error) {
	set, pcy, err = NewParser().ParsePolicyOrSet(data)
	if err != nil {
		return nil, nil, err
	}

	if set == nil && pcy != nil {
		set = &api.PolicySet{
			Policies: []*api.Policy{
				pcy,
			},
		}
	}

	set, err = compiler.CompileSet(set)
	return set, nil, err
}

// Compile builds a policy set fetching any remote pieces as necessary
func (compiler *Compiler) CompileSet(set *api.PolicySet) (*api.PolicySet, error) {
	if err := set.Validate(); err != nil {
		return nil, fmt.Errorf("validating policy set: %w", err)
	}

	// Validate PolicySet / Policies
	if err := compiler.impl.ValidateSet(&compiler.Options, set); err != nil {
		return nil, fmt.Errorf("validating policy set: %w", err)
	}

	// Extract and enrich the remote references. This step is expected to return
	// only those refs that point to remote resources and to compound the integrity
	// data (hashes) of the remote resources.
	remoteRefs, err := compiler.impl.ExtractRemoteReferences(&compiler.Options, set)
	if err != nil {
		return nil, fmt.Errorf("extracting remote refs: %w", err)
	}

	// Fetch remote resources. This retrieves the remote data but also validates
	// the signatures and/or hashes
	if err := compiler.impl.FetchRemoteResources(
		&compiler.Options, compiler.Store, remoteRefs,
	); err != nil {
		return nil, fmt.Errorf("fetching remote resources: %w", err)
	}

	// Assemble the local policy
	if err := compiler.impl.AssemblePolicySet(&compiler.Options, set, compiler.Store); err != nil {
		return nil, fmt.Errorf("error assembling policy set: %w", err)
	}

	// Validate (with remote parts)
	if err := compiler.impl.ValidateAssebledSet(&compiler.Options, set); err != nil {
		return nil, fmt.Errorf("validating assembled policy: %w", err)
	}

	// Return
	return set, nil
}

// Compile builds a policy set fetching any remote pieces as necessary
func (compiler *Compiler) CompilePolicy(set *api.Policy) (*api.Policy, error) {
	return nil, fmt.Errorf("compiling bare policies is not supported yet")
}
