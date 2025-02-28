// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package gotable transforms evaluation results to a go table object,
// from there it can be rendererd to html, markup, etc.
package gotable

import (
	"fmt"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
)

type TableBuilder struct {
	Decorator TableDecorator
}

// TableDecorator is an object that renders the format specific
// decoration of the tabular reports.
type TableDecorator interface {
	AmpelBanner(legend string) string
	SubjectToString(subject *api.ResourceDescriptor) string
	ErrorToString(err *api.Error) string
	StatusToDot(status string) string
	ControlsToString(result *api.Result, checkID, def string) string
	TenetsToString(result *api.Result) string
	Bold(string) string
}

// RenderResult renders a single evaluation result
func (tb *TableBuilder) ResultsTable(result *api.Result) (table.Writer, error) {
	t := table.NewWriter()

	rowConfigAutoMerge := table.RowConfig{
		AutoMerge:      true,
		AutoMergeAlign: text.AlignLeft,
	}
	banner := tb.Decorator.AmpelBanner("Evaluation Results")
	t.AppendRow(table.Row{banner, banner, banner}, rowConfigAutoMerge)
	t.AppendSeparator()
	t.AppendRow(table.Row{"ID", "ID", result.Policy.Id}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Status", "Status", fmt.Sprintf("%s %s", tb.Decorator.StatusToDot(result.Status), tb.Decorator.Bold(result.Status))}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Results Date", "Results Date", result.DateEnd.AsTime().Local()}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Execution Time", "Execution Time", result.DateEnd.AsTime().Sub(result.DateStart.AsTime())}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Tenets", "Tenets", tb.Decorator.TenetsToString(result)}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Subject", "Subject", tb.Decorator.SubjectToString(result.Subject)}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Controls", "Controls", tb.Decorator.ControlsToString(result, "", "")}, rowConfigAutoMerge)
	t.AppendSeparator()
	t.AppendRow(table.Row{tb.Decorator.Bold("Check"), tb.Decorator.Bold("Status"), tb.Decorator.Bold("Message")})
	t.AppendSeparator()

	for i, er := range result.EvalResults {
		t.AppendRow(
			table.Row{
				tb.Decorator.ControlsToString(result, er.Id, fmt.Sprintf("%d", i)),
				fmt.Sprintf("%s %s", tb.Decorator.StatusToDot(er.Status), er.Status),
				tb.Decorator.ErrorToString(er.Error),
			},
		)
	}
	return t, nil
}
