// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package html

import (
	"fmt"
	"io"

	"github.com/jedib0t/go-pretty/v6/table"

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
	t, err := d.TableWriter.ResultSetTable(rset)
	if err != nil {
		return fmt.Errorf("building table: %w", err)
	}

	t.SetOutputMirror(w)
	t.Style().HTML = table.HTMLOptions{
		EscapeText: false,
	}
	t.RenderHTML()
	return nil
}

func (d *Driver) RenderResult(w io.Writer, result *api.Result) error {
	t, err := d.TableWriter.ResultsTable(result)
	if err != nil {
		return fmt.Errorf("building table: %w", err)
	}
	t.SetOutputMirror(w)
	t.Style().HTML = table.HTMLOptions{
		EscapeText: false,
	}
	t.RenderHTML()
	return nil
}
