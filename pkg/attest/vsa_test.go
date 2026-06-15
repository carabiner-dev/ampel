// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	papi "github.com/carabiner-dev/policy/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// vsaShape is the minimal slice of the SLSA VSA predicate the level
// tests assert on. Binding only these fields keeps the tests robust to
// unrelated predicate growth.
type vsaShape struct {
	Predicate struct {
		VerifiedLevels []string `json:"verifiedLevels"`
		SlsaVersion    string   `json:"slsaVersion"`
	} `json:"predicate"`
}

// resultWithControls builds a passing *papi.Result for digest carrying
// the given controls, so the VSA writers have levels to lift.
func resultWithControls(digest string, controls ...*papi.Control) *papi.Result {
	return &papi.Result{
		Subject:   newSubject(digest),
		Status:    papi.StatusPASS,
		DateStart: timestamppb.Now(),
		DateEnd:   timestamppb.Now(),
		Meta:      &papi.Meta{Controls: controls},
	}
}

// emitVSA renders results as a VSA and returns the parsed predicate
// fields the tests assert on.
func emitVSA(t *testing.T, results papi.Results) vsaShape {
	t.Helper()
	var buf bytes.Buffer
	if err := New().AttestTo(&buf, results, WithFormat("vsa")); err != nil {
		t.Fatalf("AttestTo vsa: %v", err)
	}
	var got vsaShape
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshaling vsa: %v\nbody: %s", err, buf.String())
	}
	return got
}

// A WRANGLE-framework control reaches verifiedLevels on both writer
// paths, and because it is not a SLSA-track level it must not stamp
// slsaVersion on the VSA.
func TestVSA_NamespacedLevel_NoSlsaVersion(t *testing.T) {
	wrangle := &papi.Control{Framework: "WRANGLE", Id: "RELEASE_PINNED"}

	t.Run("ResultSet", func(t *testing.T) {
		rs := newResultSet(t, "deadbeef")
		rs.Results[0].Meta = &papi.Meta{Controls: []*papi.Control{wrangle}}
		got := emitVSA(t, rs)
		if !slices.Contains(got.Predicate.VerifiedLevels, "WRANGLE_RELEASE_PINNED") {
			t.Errorf("verifiedLevels = %v, want WRANGLE_RELEASE_PINNED", got.Predicate.VerifiedLevels)
		}
		if got.Predicate.SlsaVersion != "" {
			t.Errorf("slsaVersion = %q, want empty for a non-SLSA level", got.Predicate.SlsaVersion)
		}
	})

	t.Run("Result", func(t *testing.T) {
		got := emitVSA(t, resultWithControls("deadbeef", wrangle))
		if !slices.Contains(got.Predicate.VerifiedLevels, "WRANGLE_RELEASE_PINNED") {
			t.Errorf("verifiedLevels = %v, want WRANGLE_RELEASE_PINNED", got.Predicate.VerifiedLevels)
		}
		if got.Predicate.SlsaVersion != "" {
			t.Errorf("slsaVersion = %q, want empty for a non-SLSA level", got.Predicate.SlsaVersion)
		}
	})
}

// A SLSA-track control alongside a namespaced one yields both levels
// and still stamps slsaVersion (the SLSA level is what gates it).
func TestVSA_MixedLevels_StampsSlsaVersion(t *testing.T) {
	slsa := &papi.Control{Framework: "SLSA", Class: "BUILD", Id: "LEVEL_3"}
	wrangle := &papi.Control{Framework: "WRANGLE", Id: "RELEASE_PINNED"}

	t.Run("ResultSet", func(t *testing.T) {
		rs := newResultSet(t, "deadbeef")
		rs.Results[0].Meta = &papi.Meta{Controls: []*papi.Control{slsa, wrangle}}
		got := emitVSA(t, rs)
		for _, want := range []string{"SLSA_BUILD_LEVEL_3", "WRANGLE_RELEASE_PINNED"} {
			if !slices.Contains(got.Predicate.VerifiedLevels, want) {
				t.Errorf("verifiedLevels = %v, want %s", got.Predicate.VerifiedLevels, want)
			}
		}
		if got.Predicate.SlsaVersion != slsaVersion {
			t.Errorf("slsaVersion = %q, want %q", got.Predicate.SlsaVersion, slsaVersion)
		}
	})

	t.Run("Result", func(t *testing.T) {
		got := emitVSA(t, resultWithControls("deadbeef", slsa, wrangle))
		for _, want := range []string{"SLSA_BUILD_LEVEL_3", "WRANGLE_RELEASE_PINNED"} {
			if !slices.Contains(got.Predicate.VerifiedLevels, want) {
				t.Errorf("verifiedLevels = %v, want %s", got.Predicate.VerifiedLevels, want)
			}
		}
		if got.Predicate.SlsaVersion != slsaVersion {
			t.Errorf("slsaVersion = %q, want %q", got.Predicate.SlsaVersion, slsaVersion)
		}
	})
}

// A control with an empty Id has no label and must never reach
// verifiedLevels — the guard that prevents an empty-string entry once
// the SLSA_ prefix filter no longer drops it.
func TestVSA_EmptyIdControl_Dropped(t *testing.T) {
	empty := &papi.Control{Framework: "WRANGLE"}

	t.Run("ResultSet", func(t *testing.T) {
		rs := newResultSet(t, "deadbeef")
		rs.Results[0].Meta = &papi.Meta{Controls: []*papi.Control{empty}}
		got := emitVSA(t, rs)
		if slices.Contains(got.Predicate.VerifiedLevels, "") {
			t.Errorf("verifiedLevels contains an empty entry: %v", got.Predicate.VerifiedLevels)
		}
	})

	t.Run("Result", func(t *testing.T) {
		got := emitVSA(t, resultWithControls("deadbeef", empty))
		if slices.Contains(got.Predicate.VerifiedLevels, "") {
			t.Errorf("verifiedLevels contains an empty entry: %v", got.Predicate.VerifiedLevels)
		}
	})
}

// Controls from a result whose subject differs from the policyset
// subject are dependency levels, not verifiedLevels — this split must
// hold for namespaced controls just as it does for SLSA ones.
func TestVSA_NamespacedDependencyLevel(t *testing.T) {
	rs := newResultSet(t, "deadbeef")
	dep := resultWithControls("feedface", &papi.Control{Framework: "WRANGLE", Id: "RELEASE_PINNED"})
	rs.Results = append(rs.Results, dep)

	var buf bytes.Buffer
	if err := New().AttestTo(&buf, rs, WithFormat("vsa")); err != nil {
		t.Fatalf("AttestTo vsa: %v", err)
	}
	var got struct {
		Predicate struct {
			VerifiedLevels []string `json:"verifiedLevels"`
			// protojson encodes the uint64 dependency counts as strings.
			DependencyLevels map[string]string `json:"dependencyLevels"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshaling vsa: %v\nbody: %s", err, buf.String())
	}
	if got.Predicate.DependencyLevels["WRANGLE_RELEASE_PINNED"] != "1" {
		t.Errorf("dependencyLevels = %v, want WRANGLE_RELEASE_PINNED:1", got.Predicate.DependencyLevels)
	}
	if slices.Contains(got.Predicate.VerifiedLevels, "WRANGLE_RELEASE_PINNED") {
		t.Errorf("dependency level leaked into verifiedLevels: %v", got.Predicate.VerifiedLevels)
	}
}
