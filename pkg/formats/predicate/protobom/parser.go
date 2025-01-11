package protobom

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/protobom/protobom/pkg/reader"
	"github.com/puerco/ampel/pkg/attestation"
)

type Parser struct{}

// Ensure this parser implements the interface
var _ attestation.PredicateParser = (*Parser)(nil)

func New() *Parser {
	return &Parser{}
}

var PredicateTypes = []string{}

// Parse generates a generic JSON predicate object from any JSON it gets.
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	r := reader.New()
	s := bytes.NewReader(data)
	doc, err := r.ParseStream(s)
	if err != nil {
		// If it's not a supported SBOM format, catch the error and
		// return the common error to hand off to another predicate parser.
		if strings.Contains(err.Error(), "unknown SBOM format") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("parsing data: %w", err)
	}

	// Reset the predicates
	return &Predicate{
		Data:   data,
		Parsed: doc,
	}, err
}

func (p *Parser) SupportsType(testTypes ...string) bool {
	for _, pt := range PredicateTypes {
		if slices.Contains(testTypes, pt) {
			return true
		}
	}
	return false
}
