// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package attest writes attestations capturing evaluation results in
// the format chosen by the caller. It is the home for the signing
// pipeline that will turn ampel results into signed attestations —
// for now it covers the format dispatch only, so call sites that
// move to it today don't change shape when signing lands.
package attest

import (
	"errors"
	"fmt"
	"io"
	"os"

	papi "github.com/carabiner-dev/policy/api/v1"

	"github.com/carabiner-dev/ampel/internal/render"
	"github.com/carabiner-dev/ampel/pkg/verifier"
)

// ResultsAttester writes a results attestation in the configured
// format. The "ampel" format is rendered by the *verifier.Ampel
// supplied at construction; non-"ampel" formats route through the
// render engine.
type ResultsAttester struct {
	// Ampel renders the "ampel" format. Required when Format is
	// "" or "ampel"; may be nil for any other format.
	Ampel *verifier.Ampel

	// Format selects the results-attestation format. Empty defaults
	// to "ampel". Must be one of verifier.ResultsAttestationFormats;
	// callers should rely on VerificationOptions.Validate for
	// upstream rejection of unknown values.
	Format string
}

// New returns a ResultsAttester wired to ampel for the "ampel" format.
// Empty format resolves to "ampel" at attest time.
func New(ampel *verifier.Ampel, format string) *ResultsAttester {
	return &ResultsAttester{Ampel: ampel, Format: format}
}

// AttestToFile writes the results attestation for results to path,
// truncating any existing file. The file handle is closed before
// the call returns.
func (a *ResultsAttester) AttestToFile(path string, results *papi.Results) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("opening results attestation path: %w", err)
	}
	defer f.Close() //nolint:errcheck // best-effort close on a write target; AttestTo's error wins
	return a.AttestTo(f, results)
}

// AttestTo writes the results attestation for results to w. Splitting
// the writer- and path-based entry points keeps the dispatch
// testable without touching the filesystem.
func (a *ResultsAttester) AttestTo(w io.Writer, results papi.Results) error {
	switch a.Format {
	case "ampel", "":
		if a.Ampel == nil {
			return errors.New("attest: \"ampel\" format requires a configured *verifier.Ampel")
		}
		if err := a.Ampel.AttestResults(w, results); err != nil {
			return fmt.Errorf("writing results attestation: %w", err)
		}
		return nil
	default:
		eng := render.NewEngine()
		if err := eng.SetDriver(a.Format); err != nil {
			return fmt.Errorf("loading attestation driver: %w", err)
		}
		switch r := results.(type) {
		case *papi.Result:
			if err := eng.RenderResult(w, r); err != nil {
				return fmt.Errorf("rendering result: %w", err)
			}
		case *papi.ResultSet:
			if err := eng.RenderResultSet(w, r); err != nil {
				return fmt.Errorf("rendering result set: %w", err)
			}
		default:
			return errors.New("unable to determine results type to attest")
		}
		return nil
	}
}
