// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package gotable transforms evaluation results to a go table object,
// from there it can be rendererd to html, markup, etc.
package gotable

import (
	"fmt"
	"math"
	"strings"

	"github.com/carabiner-dev/attestation"
	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

type TableBuilder struct {
	Decorator TableDecorator
}

// TableDecorator is an object that renders the format specific
// decoration of the tabular reports.
type TableDecorator interface {
	AmpelBanner(string) string
	SubjectToString(attestation.Subject, []*papi.ChainedSubject) string
	AssessmentToString(*papi.Assessment) string
	ErrorToString(*papi.Error) string
	StatusToDot(string) string
	ControlsToString(result *papi.Result, checkID, def string) string
	TenetsToString(result *papi.Result) string
	Bold(string) string
}

// RenderResult renders a single evaluation result
func (tb *TableBuilder) ResultsTable(result *papi.Result) (table.Writer, error) {
	t := table.NewWriter()

	rowConfigAutoMerge := table.RowConfig{
		AutoMerge:      true,
		AutoMergeAlign: text.AlignLeft,
	}
	banner := tb.Decorator.AmpelBanner("Evaluation Results")
	t.AppendRow(table.Row{banner, banner, banner}, rowConfigAutoMerge)
	t.AppendSeparator()
	if result.Meta.Description != "" {
		txt := result.Meta.Description
		if result.Policy.Id != "" {
			txt = result.Policy.Id + ": " + txt
		}
		t.AppendRow(table.Row{txt, txt, txt}, rowConfigAutoMerge)
		t.AppendSeparator()
	} else if result.Policy.Id != "" {
		t.AppendRow(table.Row{"ID", "ID", result.Policy.Id}, rowConfigAutoMerge)
	}

	t.AppendRow(table.Row{"Status", "Status", fmt.Sprintf("%s %s", tb.Decorator.StatusToDot(result.Status), tb.Decorator.Bold(result.Status))}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Results Date", "Results Date", result.DateEnd.AsTime().Local()}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Execution Time", "Execution Time", result.DateEnd.AsTime().Sub(result.DateStart.AsTime())}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Tenets", "Tenets", tb.Decorator.TenetsToString(result)}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Subject", "Subject", tb.Decorator.SubjectToString(result.Subject, result.Chain)}, rowConfigAutoMerge)
	if len(result.GetMeta().Controls) > 0 {
		t.AppendRow(table.Row{"Controls", "Controls", tb.Decorator.ControlsToString(result, "", "")}, rowConfigAutoMerge)
	}
	t.AppendSeparator()
	t.AppendRow(table.Row{tb.Decorator.Bold("Check"), tb.Decorator.Bold("Status"), tb.Decorator.Bold("Message")})
	t.AppendSeparator()

	for i, er := range result.EvalResults {
		cell := ""
		if er.GetAssessment() != nil {
			cell = tb.Decorator.AssessmentToString(er.GetAssessment())
		}
		if er.Status != papi.StatusPASS {
			cell = tb.Decorator.ErrorToString(er.Error)
		}
		t.AppendRow(
			table.Row{
				tb.Decorator.ControlsToString(result, er.Id, fmt.Sprintf("%d", i)),
				fmt.Sprintf("%s %s", tb.Decorator.StatusToDot(er.Status), er.Status),
				cell,
			},
		)
	}
	return t, nil
}

// RenderResult renders a single evaluation result
func (tb *TableBuilder) ResultSetTable(set *papi.ResultSet) (table.Writer, error) {
	t := table.NewWriter()

	rowConfigAutoMerge := table.RowConfig{
		AutoMerge:      true,
		AutoMergeAlign: text.AlignLeft,
	}
	banner := tb.Decorator.AmpelBanner("Evaluation Results")
	t.AppendRow(table.Row{banner, banner, banner, banner}, rowConfigAutoMerge)
	t.AppendSeparator()
	t.AppendRow(table.Row{tb.Decorator.Bold("PolicySet"), set.GetPolicySet().GetId(), tb.Decorator.Bold("Date"), set.DateEnd.AsTime().Local()})
	t.AppendSeparator()
	if s := set.GetSubject(); s != nil {
		st := ""
		if s.GetName() != "" {
			st += s.GetName() + "\n"
		}
		for algo, val := range s.GetDigest() {
			// This will prevent a panic if the subject hash is short, but it should never
			strlen := math.Min(32, float64(len(val)))
			st += fmt.Sprintf("- %s:%s...\n", algo, val[0:int(strlen)])
		}
		st = strings.TrimSuffix(st, "\n")
		t.AppendRow(
			table.Row{
				fmt.Sprintf("Status: %s %s", tb.Decorator.StatusToDot(set.Status), tb.Decorator.Bold(set.Status)),
				"Subject", st, st,
			},
			rowConfigAutoMerge,
		)
	}
	t.AppendSeparator()
	t.AppendRow(table.Row{tb.Decorator.Bold("Policy"), tb.Decorator.Bold("Controls"), tb.Decorator.Bold("Status"), tb.Decorator.Bold("Details")})
	t.AppendSeparator()
	for _, r := range set.GetResults() {
		assessments := ""
		for _, er := range r.GetEvalResults() {
			if er.GetStatus() == papi.StatusPASS && r.GetStatus() == papi.StatusPASS {
				assessments += er.GetAssessment().GetMessage() + "\n"
			} else if er.GetStatus() != papi.StatusPASS && r.GetStatus() != papi.StatusPASS {
				if !strings.Contains(assessments, er.GetError().GetMessage()+"\n") {
					tb.Decorator.ErrorToString(er.GetError())
				}
			}
		}
		assessments = strings.TrimSuffix(assessments, "\n")

		controls := "-"
		if len(r.GetMeta().GetControls()) > 0 {
			controls = tb.Decorator.ControlsToString(r, "", "")
		}
		t.AppendRow(
			table.Row{
				r.GetPolicy().GetId(),
				controls,
				fmt.Sprintf("%s %s", tb.Decorator.StatusToDot(r.Status), tb.Decorator.Bold(r.Status)),
				assessments,
			},
		)
	}
	return t, nil
}
