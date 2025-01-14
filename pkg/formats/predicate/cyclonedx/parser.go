package cyclonedx

import (
	"bytes"
	"errors"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate/json"
)

type Parser struct{}

// Ensure this parser implements the interface
var _ attestation.PredicateParser = (*Parser)(nil)

func New() *Parser {
	return &Parser{}
}

var PredicateType = attestation.PredicateType("https://cyclonedx.org/bom")

// Parse generates a generic JSON predicate object from any JSON it gets.
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	r := bytes.NewReader(data)
	sniffer := formats.Sniffer{}
	format, err := sniffer.SniffReader(r)
	if err != nil {
		// TODO(puerco): Swap this to a new error type
		if errors.Is(err, errors.New("unknown SBOM format")) {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, err
	}

	if format.Encoding() != "json" {
		return nil, attestation.ErrNotCorrectFormat
	}

	if format.Type() != formats.CDXFORMAT {
		return nil, attestation.ErrNotCorrectFormat
	}

	pred, err := json.New(json.WithJson(data), json.WithType(PredicateType))
	if err != nil {
		return nil, err
	}
	return pred, nil
}
func (p *Parser) SupportsType(predTypes ...string) bool {
	for _, t := range predTypes {
		if t != string(PredicateType) {
			return false
		}
	}
	return true
}
