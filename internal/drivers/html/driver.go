// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package html

import (
	"fmt"
	"io"

	"github.com/carabiner-dev/ampel/internal/drivers/gotable"
	api "github.com/carabiner-dev/ampel/pkg/api/v1"
)

func New() *Driver {
	return &Driver{
		TableWriter: gotable.TableBuilder{
			Decorator: &Decorator{},
		},
	}
}

type Driver struct {
	TableWriter gotable.TableBuilder
}

// RenderResultSet takes a resultset
func (d *Driver) RenderResultSet(w io.Writer, rset *api.ResultSet) error {
	for _, result := range rset.Results {
		t, err := d.TableWriter.ResultsTable(result)
		if err != nil {
			return fmt.Errorf("building table: %w", err)
		}

		t.SetOutputMirror(w)
		t.RenderHTML()
	}
	return nil
}

func (d *Driver) RenderResult(w io.Writer, result *api.Result) error {
	t, err := d.TableWriter.ResultsTable(result)
	if err != nil {
		return fmt.Errorf("building table: %w", err)
	}
	t.SetOutputMirror(w)
	t.RenderHTML()
	return nil
}
