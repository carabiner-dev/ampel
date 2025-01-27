// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package filesystem implements an attestation collector from a fs.FS
package filesystem

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/collector/filter"
	"github.com/puerco/ampel/pkg/formats/envelope"
)

func New(iofs fs.FS) *Collector {
	return &Collector{
		FS: iofs,
	}
}

// Collector is the filesystem collector
type Collector struct {
	FS fs.FS
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(*filter.AttestationQuery) ([]attestation.Envelope, error) {
	if c.FS == nil {
		return nil, errors.New("collector has no filesystem defined")
	}
	ret := []attestation.Envelope{}

	// Walk the filesystem and read any attestations
	if err := fs.WalkDir(c.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Read the file data from the filesystem
		bs, err := fs.ReadFile(c.FS, path)
		if err != nil {
			return fmt.Errorf("reading file from fs: %w", err)
		}

		// Pass the read data to all the enabled parsers
		attestations, err := envelope.Parsers.Parse(bytes.NewReader(bs))
		if err != nil {
			return fmt.Errorf("parsing file: %w", err)
		}
		ret = append(ret, attestations...)

		return nil
	}); err != nil {
		return nil, fmt.Errorf("scanning filesystem: %w", err)
	}
	return ret, nil
}

// FetchObjectStatements
func (c *Collector) FetchObjectStatements(attestation.Subject) ([]attestation.Envelope, error) {
	return nil, nil
}
