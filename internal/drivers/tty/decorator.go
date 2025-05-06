// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package tty

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	gww "github.com/mitchellh/go-wordwrap"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
)

type Decorator struct{}

// Color functions
var (
	r  = color.New(color.FgRed, color.BgBlack).SprintFunc()
	y  = color.New(color.FgYellow, color.BgBlack).SprintFunc()
	g  = color.New(color.FgGreen, color.BgBlack).SprintFunc()
	w1 = color.New(color.FgHiWhite, color.BgBlack).SprintFunc()
	w2 = color.New(color.Faint, color.FgWhite, color.BgBlack).SprintFunc()
)

func (d *Decorator) AssessmentToString(a *api.Assessment) string {
	return w2("✔ " + a.GetMessage())
}

func (d *Decorator) AmpelBanner(legend string) string {
	if legend != "" {
		legend = w2(": " + legend)
	}
	return fmt.Sprintf("%s%s%s%s%s", r("⬤"), y("⬤"), g("⬤"), w1(strings.ToUpper("AMPEL")), legend)
}

func (d *Decorator) StatusToDot(status string) string {
	switch status {
	case api.StatusFAIL:
		return r("●")
	case api.StatusPASS:
		return g("●")
	case api.StatusSOFTFAIL:
		return y("●")
	default:
		return "?"
	}
}

func (d *Decorator) SubjectToString(subject *api.ResourceDescriptor, chain []*api.ChainedSubject) string {
	predata := ""
	for _, subsubj := range chain {
		predata += d.SubjectToString(subsubj.Source, nil) + "\n↳ "
	}
	if subject == nil {
		return predata + "(N/A)"
	}

	if subject.Name != "" {
		ret := predata + subject.Name
		for algo, val := range subject.Digest {
			ret += fmt.Sprintf("\n  %s:%s...", algo, val[0:32])
		}
		return ret
	}

	if subject.Uri != "" {
		return predata + subject.Uri
	}

	for algo, val := range subject.Digest {
		return predata + fmt.Sprintf("%s:%s", algo, val)
	}
	return predata + ""
}

func (d *Decorator) ErrorToString(err *api.Error) string {
	if err == nil {
		return ""
	}

	res := err.Message
	if err.Guidance != "" {
		res += "\n" + gww.WrapString(err.Guidance, 55)
	}
	return res
}

func (d *Decorator) ControlsToString(result *api.Result, checkID, def string) string {
	checks := []string{}
	for _, c := range result.Meta.Controls {
		ret := ""
		ret += c.Class
		if c.Class != "" {
			ret += "-"
		}
		ret += c.Id

		if checkID != "" {
			ret += "." + checkID
		} else if def != "" {
			ret = "--"
		}
		checks = append(checks, strings.TrimSpace(ret))
	}
	return strings.Join(checks, "\n")
}

func (d *Decorator) TenetsToString(result *api.Result) string {
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

	statuses := []string{}
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

func (d *Decorator) Bold(txt string) string {
	return w1(txt)
}
