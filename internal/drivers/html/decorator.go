// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package html

import (
	"fmt"
	"strings"

	"github.com/carabiner-dev/attestation"
	papi "github.com/carabiner-dev/policy/api/v1"
)

// Decorator implements the tabnle decorator interface to style the output
type Decorator struct{}

func (d *Decorator) AssessmentToString(a *papi.Assessment) string {
	return a.Message
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
	case papi.StatusFAIL:
		return "🔴"
	case papi.StatusPASS:
		return "🟢"
	case papi.StatusSOFTFAIL:
		return "🟡"
	default:
		return "?"
	}
}

func (d *Decorator) SubjectToString(subject attestation.Subject, chain []*papi.ChainedSubject) string {
	predata := ""
	for _, subsubj := range chain {
		predata += d.SubjectToString(subsubj.Source, nil) + "<br>\n↳ "
	}

	if subject == nil {
		return predata + "(N/A)"
	}

	if subject.GetName() != "" {
		return predata + subject.GetName()
	}

	if subject.GetUri() != "" {
		return predata + subject.GetUri()
	}

	for algo, val := range subject.GetDigest() {
		return predata + fmt.Sprintf("%s:%s", algo, val)
	}
	return predata + ""
}

func (d *Decorator) ErrorToString(err *papi.Error) string {
	if err == nil {
		return ""
	}

	res := err.Message
	if err.Guidance != "" {
		res += "<br />\n" + err.Guidance
	}
	return res
}

func (d *Decorator) ControlsToString(result *papi.Result, checkID, def string) string {
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

func (d *Decorator) TenetsToString(result *papi.Result) string {
	ret := fmt.Sprintf("%d ", len(result.EvalResults))
	var pass, fail, softfail int
	for _, r := range result.EvalResults {
		switch r.Status {
		case papi.StatusFAIL:
			fail++
		case papi.StatusSOFTFAIL:
			softfail++
		case papi.StatusPASS:
			pass++
		}
	}

	statuses := []string{}
	if pass > 0 {
		statuses = append(statuses, fmt.Sprintf("%d %s", pass, papi.StatusPASS))
	}
	if softfail > 0 {
		statuses = append(statuses, fmt.Sprintf("%d %s", softfail, papi.StatusSOFTFAIL))
	}
	if fail > 0 {
		statuses = append(statuses, fmt.Sprintf("%d %s", fail, papi.StatusFAIL))
	}
	ret += fmt.Sprintf("(%s)", strings.Join(statuses, " | "))
	ret += " Mode: " + result.Meta.AssertMode
	return ret
}
