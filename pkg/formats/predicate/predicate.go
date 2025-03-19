// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicate

import (
	"errors"
	"fmt"
	"slices"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/ampel"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/cyclonedx"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/json"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/openeox"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/openvex"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/osv"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/protobom"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/slsa"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/spdx"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/trivy"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/vulns"
	"github.com/sirupsen/logrus"
)

var ErrWrongEncoding = errors.New("wrong data encoding, should be text/json")

type ParsersList map[attestation.PredicateType]attestation.PredicateParser

// Parsers
var Parsers = ParsersList{
	protobom.PredicateType:       protobom.New(),
	spdx.PredicateType:           spdx.New(),
	cyclonedx.PredicateType:      cyclonedx.New(),
	ampel.PredicateTypeResults:   ampel.New(),
	ampel.PredicateTypePolicy:    ampel.New(),
	ampel.PredicateTypePolicySet: ampel.New(),
	vulns.PredicateType:          vulns.New(),
	trivy.PredicateType:          trivy.New(),
	osv.PredicateType:            osv.New(),
	openvex.PredicateType:        openvex.New(),
	openeox.PredicateType:        openeox.New(),
	slsa.PredicateType10:         slsa.NewParserV10(),
	slsa.PredicateType10:         slsa.NewParserV11(),
	slsa.PredicateType02:         slsa.NewParserV02(),
}

type ParseOption func(*Options)

type Options struct {
	// Default to JSON will cause the predicate to be parsed as
	// plain JSON is no parser can handle it.
	DefaultToJSON bool

	// TypeHints is an array of types that defines which parser will be tried.
	// If no TypeHints are defined, ampel will try to parse the predicate with
	// all loaded parsers.
	TypeHints []attestation.PredicateType
}

func WithDefaulToJSON(sino bool) ParseOption {
	return func(o *Options) {
		o.DefaultToJSON = sino
	}
}

func WithTypeHints(hints []attestation.PredicateType) ParseOption {
	return func(o *Options) {
		o.TypeHints = hints
	}
}

func (pl *ParsersList) GetTypeParsers(predicateTypes []attestation.PredicateType) *ParsersList {
	ret := ParsersList{}
	for t, p := range *pl {
		if p.SupportsType(predicateTypes...) {

		}
		if slices.Contains(predicateTypes, t) {
			ret[t] = p
		}
	}
	return &ret
}

var defaultOpts = Options{
	DefaultToJSON: true,
	TypeHints:     []attestation.PredicateType{},
}

// Parse gets a byte slice with a predicate and tries to parse ir with the loaded
// parsers.
func (pl *ParsersList) Parse(data []byte, optFn ...ParseOption) (attestation.Predicate, error) {
	opts := defaultOpts
	for _, o := range optFn {
		o(&opts)
	}
	var ps = pl
	if len(opts.TypeHints) > 0 {
		ps = pl.GetTypeParsers(opts.TypeHints)
		logrus.Debugf("loaded %d parsers after applying type hints", len(*ps))
	}

	var errs = []error{}
	for f, p := range *ps {
		logrus.Debugf("Checking if predicate is %s", f)
		// If we have predicate type hints, check if the parser can handle them
		if len(opts.TypeHints) > 0 && !p.SupportsType(opts.TypeHints...) {
			logrus.Debug("  ... not supported by parser?!")
			continue
		}

		pred, err := p.Parse(data)
		if err == nil {
			logrus.Debugf("Found predicate of type %s", f)
			return pred, nil
		}

		if !errors.Is(err, attestation.ErrNotCorrectFormat) {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	// by now we default to JSON unless the options say don't
	if !opts.DefaultToJSON {
		return nil, fmt.Errorf("unkown predictate type")
	}

	// Finally try the vanilla JSON parser
	p := &json.Parser{}
	pred, err := p.Parse(data)
	if err != nil {
		return nil, err
	}
	logrus.Debug("Predicate parsed as generic JSON type")
	return pred, nil
}
