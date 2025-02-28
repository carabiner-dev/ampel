// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package tty

import (
	"fmt"
	"io"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	gww "github.com/mitchellh/go-wordwrap"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
)

func New() *Driver {
	return &Driver{}
}

type Driver struct{}

var r = color.New(color.FgRed, color.BgBlack).SprintFunc()
var y = color.New(color.FgYellow, color.BgBlack).SprintFunc()
var g = color.New(color.FgGreen, color.BgBlack).SprintFunc()

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

// RenderResult renders a single evaluation result
func (d *Driver) RenderResult(w io.Writer, result *api.Result) error {

	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.AppendHeader(table.Row{"Check", "Status", "Message"})

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
	for _, c := range result.Controls {
		ret += c.Class
		if c.Class != "" {
			ret += "-"
		}
		ret += c.Id

		if checkID != "" {
			ret += "." + checkID
		} else {
			ret += fmt.Sprintf(" (%s)", def)
		}
	}
	return ret
}
