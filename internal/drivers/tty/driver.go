// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package tty

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	gww "github.com/mitchellh/go-wordwrap"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
)

func New() *Driver {
	return &Driver{}
}

type Driver struct{}

// Color functions
var r = color.New(color.FgRed, color.BgBlack).SprintFunc()
var y = color.New(color.FgYellow, color.BgBlack).SprintFunc()
var g = color.New(color.FgGreen, color.BgBlack).SprintFunc()
var w1 = color.New(color.FgHiWhite, color.BgBlack).SprintFunc()
var w2 = color.New(color.Faint, color.FgWhite, color.BgBlack).SprintFunc()

func status2Dot(status string) string {
	switch status {
	case api.StatusFAIL:
		return r("⬤")
	case api.StatusPASS:
		return g("⬤")
	case api.StatusSOFTFAIL:
		return y("⬤")
	default:
		return "?"
	}
}

// RenderResultSet takes a resultset
func (d *Driver) RenderResultSet(w io.Writer, rset *api.ResultSet) error {
	// return d.RenderResultSet(w, rset)
	for _, result := range rset.Results {
		if err := d.RenderResult(w, result); err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) AmpelBanner(legend string) string {
	if legend != "" {
		legend = w2(": " + legend)
	}
	return fmt.Sprintf("%s%s%s%s%s", r("⬤"), y("⬤"), g("⬤"), w1(strings.ToUpper("AMPEL")), legend)
}

// RenderResult renders a single evaluation result
func (d *Driver) RenderResult(w io.Writer, result *api.Result) error {

	t := table.NewWriter()
	t.SetOutputMirror(w)
	rowConfigAutoMerge := table.RowConfig{
		AutoMerge:      true,
		AutoMergeAlign: text.AlignLeft,
	}
	banner := d.AmpelBanner("Evaluation Results")
	t.AppendRow(table.Row{banner, banner, banner}, rowConfigAutoMerge)
	t.AppendSeparator()
	t.AppendRow(table.Row{"ID", "ID", result.Policy.Id}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Status", "Status", fmt.Sprintf("%s %s", status2Dot(result.Status), w1(result.Status))}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Results Date", "Results Date", result.DateEnd.AsTime().Local()}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Execution Time", "Execution Time", result.DateEnd.AsTime().Sub(result.DateStart.AsTime())}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Tenets", "Tenets", tenets2String(result)}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Subject", "Subject", subject2string(result.Subject)}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Controls", "Controls", controls2String(result, "", "")}, rowConfigAutoMerge)
	t.AppendSeparator()
	t.AppendRow(table.Row{w1("Check"), w1("Status"), w1("Message")})
	t.AppendSeparator()

	for i, er := range result.EvalResults {
		t.AppendRow(
			table.Row{
				controls2String(result, er.Id, fmt.Sprintf("%d", i)),
				fmt.Sprintf("%s %s", status2Dot(er.Status), er.Status),
				error2string(er.Error),
			},
		)
	}
	t.Render()
	return nil
}

func subject2string(subject *api.ResourceDescriptor) string {
	if subject == nil {
		return "(N/A)"
	}

	if subject.Name != "" {
		return subject.Name
	}

	if subject.Uri != "" {
		return subject.Uri
	}

	for algo, val := range subject.Digest {
		return fmt.Sprintf("%s:%s", algo, val)
	}
	return ""
}

func error2string(err *api.Error) string {
	if err == nil {
		return ""
	}

	res := err.Message
	if err.Guidance != "" {
		res += "\n" + gww.WrapString(err.Guidance, 55)
	}
	return res
}

func controls2String(result *api.Result, checkID, def string) string {
	ret := ""
	for _, c := range result.Meta.Controls {
		ret += c.Class
		if c.Class != "" {
			ret += "-"
		}
		ret += c.Id

		if checkID != "" {
			ret += "." + checkID
		} else if def != "" {
			ret += fmt.Sprintf(" (%s)", def)
		}
	}
	return ret
}

func tenets2String(result *api.Result) string {
	ret := fmt.Sprintf("%d ", len(result.EvalResults))
	var pass, fail, softfail int
	for _, r := range result.EvalResults {
		switch r.Status {
		case api.StatusFAIL:
			fail++
		case api.StatusSOFTFAIL:
			softfail++
		case api.StatusPASS:
			pass++
		}
	}

	var statuses = []string{}
	if pass > 0 {
		statuses = append(statuses, fmt.Sprintf("%d %s", pass, api.StatusPASS))
	}
	if softfail > 0 {
		statuses = append(statuses, fmt.Sprintf("%d %s", softfail, api.StatusSOFTFAIL))
	}
	if fail > 0 {
		statuses = append(statuses, fmt.Sprintf("%d %s", fail, api.StatusFAIL))
	}
	ret += fmt.Sprintf("(%s)", strings.Join(statuses, " | "))
	ret += " Mode: " + result.Meta.AssertMode
	return ret
}
