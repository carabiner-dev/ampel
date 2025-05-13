// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"io"
	"os"

	"google.golang.org/protobuf/encoding/protojson"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
)

type CompilerOptions struct {
	// TODO: No remote data
	// TODO: Fail merging on unknown remote tenet ids
}

type Compiler struct {
	Options CompilerOptions
	Store   StorageBackend
	impl    compilerImplementation
}

func NewCompiler() (*Compiler, error) {
	opts := CompilerOptions{}
	return &Compiler{
		Options: opts,
		Store:   newRefStore(),
		impl:    &defaultCompilerImpl{},
	}, nil
}

// CompileFile takes a path to a file and returnes a compiled policyset
func (compiler *Compiler) CompileFile(path string) (*api.PolicySet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening policy file: %w", err)
	}

	return compiler.CompileReader(f)
}

func (compiler *Compiler) CompileReader(r io.Reader) (*api.PolicySet, error) {
	set := &api.PolicySet{}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading policy data: %w", err)
	}

	unmarshaller := protojson.UnmarshalOptions{
		AllowPartial:   false,
		DiscardUnknown: false,
	}

	// Unmarshall the policy source
	if err := unmarshaller.Unmarshal(data, set); err != nil {
		return nil, fmt.Errorf("unmarshalling policy: %w", err)
	}

	return compiler.Compile(set)
}

// Compile builds a policy set fetching any remote pieces as necessary
func (compiler *Compiler) Compile(set *api.PolicySet) (*api.PolicySet, error) {
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
