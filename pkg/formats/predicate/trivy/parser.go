package trivy

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/puerco/ampel/pkg/attestation"
)

type Parser struct{}

var _ attestation.PredicateParser = (*Parser)(nil)

func New() *Parser {
	return &Parser{}
}

var PredicateType = attestation.PredicateType("https://trivy.dev/report")

func (*Parser) SupportsType(predTypes ...string) bool {
	return slices.Contains(predTypes, string(PredicateType))
}

func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	var report = &TrivyReport{}
	if err := json.Unmarshal(data, report); err != nil {
		return nil, fmt.Errorf("unmarshalling trivy report: %w", err)
	}
	return &Predicate{
		Parsed: report,
		Data:   data,
	}, nil
}

func (*Predicate) GetType() attestation.PredicateType {
	return PredicateType
}

func (p *Predicate) GetData() []byte {
	return p.Data
}

func (p *Predicate) GetParsed() any {
	return p.Parsed
}
