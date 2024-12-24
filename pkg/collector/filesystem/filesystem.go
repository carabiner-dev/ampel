// Package filesystem implements an attestation collector from a filesystem

package filesystem

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/collector/filter"
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
		fmt.Println(path)
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
