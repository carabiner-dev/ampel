// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package markdown

import (
	"fmt"
	"strings"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	v1 "github.com/carabiner-dev/ampel/pkg/api/v1"
)

// Decorator implements the tabnle decorator interface to style the output
type Decorator struct{}

func (d *Decorator) AssessmentToString(a *api.Assessment) string {
	return fmt.Sprintf("✔️ _%s_", a.GetMessage())
}

func (d *Decorator) AmpelBanner(legend string) string {
	if legend != "" {
		legend = ": " + legend
	}
	return fmt.Sprintf("🔴🟡🟢<b>AMPEL</b>%s", legend)
}

func (d *Decorator) Bold(txt string) string {
	return fmt.Sprintf("<b>%s</b>", txt)
}

func (d *Decorator) StatusToDot(status string) string {
	switch status {
	case api.StatusFAIL:
		return "🔴"
	case api.StatusPASS:
		return "🟢"
	case api.StatusSOFTFAIL:
		return "🟡"
	default:
		return "?"
	}
}

func (d *Decorator) SubjectToString(subject *api.ResourceDescriptor, chain []*v1.ChainedSubject) string {
	predata := ""
	for _, subsubj := range chain {
		predata += d.SubjectToString(subsubj.Source, nil) + "<br>\n↳ "
	}

	if subject == nil {
		return predata + "(N/A)"
	}

	if subject.Name != "" {
		return predata + subject.Name
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
		res += "<br />\n" + err.Guidance
	}
	return res
}

func (d *Decorator) ControlsToString(result *api.Result, checkID, def string) string {
	ret := ""
	for _, c := range result.Meta.Controls {
		if ret != "" {
			ret += "<br />\n"
		}
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
