package osv

import (
	"fmt"
	"slices"

	"github.com/puerco/ampel/pkg/attestation"
	protoOSV "github.com/puerco/ampel/pkg/osv"
	"google.golang.org/protobuf/encoding/protojson"
)

type Parser struct{}

var _ attestation.PredicateParser = (*Parser)(nil)

func New() *Parser {
	return &Parser{}
}

// SupportsType returns true if the OSV parser supports a type
func (*Parser) SupportsType(predTypes ...string) bool {
	return slices.Contains(predTypes, string(PredicateType))
}

// Parse parses a byte slice into a OSV predicate
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	var report = &protoOSV.Predicate{}

	if err := protojson.Unmarshal(data, report); err != nil {
		return nil, fmt.Errorf("unmarshalling OSV report: %w", err)
	}
	return &Predicate{
		Parsed: report,
		Data:   data,
	}, nil
}
