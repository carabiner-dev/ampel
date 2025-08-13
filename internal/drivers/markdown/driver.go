// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package markdown

import (
	"fmt"
	"io"

	papi "github.com/carabiner-dev/policy/api/v1"

	"github.com/carabiner-dev/ampel/internal/drivers/gotable"
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
func (d *Driver) RenderResultSet(w io.Writer, rset *papi.ResultSet) error {
	for _, result := range rset.Results {
		t, err := d.TableWriter.ResultsTable(result)
		if err != nil {
			return fmt.Errorf("building table: %w", err)
		}

		t.SetOutputMirror(w)
		t.RenderMarkdown()
	}
	return nil
}

func (d *Driver) RenderResult(w io.Writer, result *papi.Result) error {
	t, err := d.TableWriter.ResultsTable(result)
	if err != nil {
		return fmt.Errorf("building table: %w", err)
	}
	t.SetOutputMirror(w)
	t.RenderMarkdown()
	return nil
}
