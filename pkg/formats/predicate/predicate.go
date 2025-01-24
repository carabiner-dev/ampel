package predicate

import (
	"errors"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate/ampel"
	"github.com/puerco/ampel/pkg/formats/predicate/cyclonedx"
	"github.com/puerco/ampel/pkg/formats/predicate/json"
	"github.com/puerco/ampel/pkg/formats/predicate/openeox"
	"github.com/puerco/ampel/pkg/formats/predicate/openvex"
	"github.com/puerco/ampel/pkg/formats/predicate/osv"
	"github.com/puerco/ampel/pkg/formats/predicate/protobom"
	"github.com/puerco/ampel/pkg/formats/predicate/spdx"
	"github.com/puerco/ampel/pkg/formats/predicate/trivy"
	"github.com/puerco/ampel/pkg/formats/predicate/vulns"
	"github.com/sirupsen/logrus"
)

var ErrWrongEncoding = errors.New("wrong data encoding, should be text/json")

type ParsersList map[attestation.PredicateType]attestation.PredicateParser

// Parsers
var Parsers = ParsersList{
	protobom.PredicateType:  protobom.New(),
	spdx.PredicateType:      spdx.New(),
	cyclonedx.PredicateType: cyclonedx.New(),
	ampel.PredicateType:     ampel.New(),
	vulns.PredicateType:     vulns.New(),
	trivy.PredicateType:     trivy.New(),
	osv.PredicateType:       osv.New(),
	openvex.PredicateType:   openvex.New(),
	openeox.PredicateType:   openeox.New(),
}

type Options struct {
	TypeHints []string
}

func (pl *ParsersList) Parse(data []byte) (attestation.Predicate, error) {
	var errs = []error{}
	for f, p := range *pl {
		logrus.Debugf("Checking if predicate is %s", f)
		pred, err := p.Parse(data)
		if err == nil {
			logrus.Infof("Found predicate of type %s", f)
			return pred, nil
		}

		// If we have predicate type hints, check if the parser can handle them
		if !p.SupportsType() {
			continue
		}

		if !errors.Is(err, attestation.ErrNotCorrectFormat) {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	// Finally try the vanilla JSON parser
	p := &json.Parser{}
	pred, err := p.Parse(data)
	if err != nil {
		return nil, err
	}
	logrus.Warning("Treating predicate as generic JSON type")
	return pred, nil
}
