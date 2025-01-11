package protobom

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/protobom/protobom/pkg/reader"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate/protobom"
	"google.golang.org/protobuf/encoding/protojson"
)

type Transformer struct{}

func New() *Transformer {
	return &Transformer{}
}

var PredicateTypes = []string{}

// Transformer generates a protobom predicate from any of the supported SBOM
// formats.
func (p *Transformer) Default(preds []attestation.Predicate) (attestation.Predicate, error) {
	r := reader.New()
	s := bytes.NewReader(preds[0].GetData())
	doc, err := r.ParseStream(s)
	if err != nil {
		// If it's not a supported SBOM format, catch the error and
		// return the common error to hand off to another predicate parser.
		if strings.Contains(err.Error(), "unknown SBOM format") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("parsing data: %w", err)
	}
	bdata, err := protojson.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshaling rendered protobom predicate: %w", err)
	}
	// Reset the predicates
	return &protobom.Predicate{
		Data:   bdata,
		Parsed: doc,
	}, err
}

// func (p *Parser) SupportsType(testTypes ...string) bool {
// 	for _, pt := range PredicateTypes {
// 		if slices.Contains(testTypes, pt) {
// 			return true
// 		}
// 	}
// 	return false
// }
