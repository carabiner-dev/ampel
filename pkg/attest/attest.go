// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package attest writes attestations capturing evaluation results in
// the format chosen by the caller. It is the home for the signing
// pipeline that will turn ampel results into signed attestations —
// for now it covers the format dispatch and intoto statement
// construction so call sites that move to it today don't change shape
// when signing lands.
package attest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/statement/intoto"
	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/carabiner-dev/predicates"
)

// ampelVerifierID is the verifier identifier embedded in every
// attestation produced by this package (VSA, SVR, and the ampel
// resultset format).
const ampelVerifierID = "https://carabiner.dev/ampel@v1"

// ResultsAttester writes a results attestation in the format chosen
// per call via WithFormat. The "ampel" format produces an in-toto
// statement carrying a predicates.ResultSet; "vsa" and "svr" route
// through their format-specific drivers.
//
// The struct is a placeholder for instance-level configuration that
// spans multiple attestation calls — signer credentials, retry
// behavior, and so on — that will land alongside signing support.
type ResultsAttester struct{}

// New returns a ready-to-use ResultsAttester.
func New() *ResultsAttester {
	return &ResultsAttester{}
}

// FnOpt configures a single Attest* call.
type FnOpt func(*attestOptions)

// attestOptions holds the per-call configuration produced by FnOpts.
type attestOptions struct {
	format      string
	prettyPrint bool
}

// defaultAttestOptions returns the baseline per-call config used when
// no FnOpts are supplied.
func defaultAttestOptions() attestOptions {
	return attestOptions{format: "ampel", prettyPrint: true}
}

// WithFormat selects the results-attestation format for the call.
// Must be one of verifier.ResultsAttestationFormats. Empty resolves
// to "ampel" at dispatch, so passing through an unset
// AttestFormat option is safe.
func WithFormat(format string) FnOpt {
	return func(o *attestOptions) {
		o.format = format
	}
}

// WithPrettyPrint controls JSON formatting of the produced
// attestation. The default is true (2-space indented output);
// pass false for a single-line compact form suitable for piping
// or one-line-per-record archives.
func WithPrettyPrint(enabled bool) FnOpt {
	return func(o *attestOptions) {
		o.prettyPrint = enabled
	}
}

// AttestToFile writes the results attestation for results to path,
// truncating any existing file. The file handle is closed before
// the call returns. Format selection is per-call via WithFormat;
// the default is "ampel".
func (a *ResultsAttester) AttestToFile(path string, results papi.Results, opts ...FnOpt) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("opening results attestation path: %w", err)
	}
	defer f.Close() //nolint:errcheck // best-effort close on a write target; AttestTo's error wins
	return a.AttestTo(f, results, opts...)
}

// AttestTo writes the results attestation for results to w. Splitting
// the writer- and path-based entry points keeps the dispatch
// testable without touching the filesystem.
func (a *ResultsAttester) AttestTo(w io.Writer, results papi.Results, opts ...FnOpt) error {
	o := defaultAttestOptions()
	for _, fn := range opts {
		fn(&o)
	}
	switch o.format {
	case "ampel", "":
		return a.attestAmpel(w, results, o)
	case "vsa":
		return a.attestVSA(w, results, o)
	case "svr":
		return a.attestSVR(w, results, o)
	default:
		return fmt.Errorf("unknown attestation format %q", o.format)
	}
}

// attestAmpel writes an "ampel"-format results attestation. Result
// and ResultGroup inputs are wrapped into a single-entry ResultSet
// before serialization so every output is the same shape.
func (a *ResultsAttester) attestAmpel(w io.Writer, results papi.Results, o attestOptions) error {
	switch r := results.(type) {
	case *papi.Result:
		rs := &papi.ResultSet{
			Results:   []*papi.Result{r},
			DateStart: r.DateStart,
			DateEnd:   r.DateEnd,
		}
		if err := rs.Assert(); err != nil {
			return fmt.Errorf("asserting results set: %w", err)
		}
		return writeResultSet(w, rs, o)
	case *papi.ResultSet:
		return writeResultSet(w, r, o)
	case *papi.ResultGroup:
		rs := &papi.ResultSet{
			Groups:    []*papi.ResultGroup{r},
			DateStart: r.DateStart,
			DateEnd:   r.DateEnd,
		}
		if err := rs.Assert(); err != nil {
			return fmt.Errorf("asserting results set: %w", err)
		}
		return writeResultSet(w, rs, o)
	default:
		return errors.New("results are not Result, ResultSet or ResultGroup")
	}
}

// writeStatementJSON serializes stmt to w in either 2-space indented
// or compact single-line JSON. Used by every format-specific writer
// so the WithPrettyPrint behavior stays consistent across ampel, VSA
// and SVR output.
func writeStatementJSON(w io.Writer, stmt *intoto.Statement, pretty bool) error {
	var (
		data []byte
		err  error
	)
	if pretty {
		data, err = json.MarshalIndent(stmt, "", "  ")
	} else {
		data, err = json.Marshal(stmt)
	}
	if err != nil {
		return fmt.Errorf("serializing statement: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing statement: %w", err)
	}
	return nil
}

// writeResultSet builds an in-toto statement carrying a
// predicates.ResultSet and writes it as JSON to w. Subjects are
// drawn from each Result's first Chain entry when present, with
// per-digest deduplication so a ResultSet covering many results
// against the same subject doesn't repeat it.
func writeResultSet(w io.Writer, resultset *papi.ResultSet, o attestOptions) error {
	if resultset == nil {
		return errors.New("unable to attest results, set is nil")
	}

	stmt := intoto.NewStatement()

	// TODO(puerco): This should probably be a method of the results set
	seen := []string{}
	for _, result := range resultset.Results {
		subject := result.Subject
		if len(result.Chain) > 0 {
			subject = result.Chain[0].Source
		}

		// If we already saw it, skip.
		if slices.Contains(seen, stringifyDigests(subject)) {
			continue
		}
		seen = append(seen, stringifyDigests(subject))

		haveMatching := false
		for _, s := range stmt.Subject {
			if attestation.SubjectsMatch(s, subject) {
				haveMatching = true
				break
			}
		}
		if !haveMatching {
			stmt.AddSubject(subject)
		}
	}

	stmt.PredicateType = predicates.PredicateTypeResultSet
	stmt.Predicate = &predicates.ResultSet{Parsed: resultset}

	return writeStatementJSON(w, stmt, o.prettyPrint)
}

// stringifyDigests returns a canonical algo:value/algo:value... form
// of subject's digest map suitable for set-membership checks.
func stringifyDigests(subject attestation.Subject) string {
	digest := subject.GetDigest()
	s := make([]string, 0, len(digest))
	for algo, val := range digest {
		s = append(s, fmt.Sprintf("%s:%s", algo, val))
	}
	slices.Sort(s)
	return strings.Join(s, "/")
}
