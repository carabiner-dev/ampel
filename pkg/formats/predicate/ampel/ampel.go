package ampel

import (
	"encoding/json"
	"fmt"
	"slices"

	api "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"google.golang.org/protobuf/encoding/protojson"
)

var PredicateType = attestation.PredicateType("https://carabiner.dev/predicate/v0.0.1")

func NewPredicate() *Predicate {
	return &Predicate{}
}

type Predicate struct {
	Data   []byte `json:"-"`
	Parsed *api.ResultSet
}

func (p *Predicate) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Parsed)
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

func New() *Parser {
	return &Parser{}
}

type Parser struct{}

// Parse reads a data slice and unmarshals it into an ampel predicate
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	set := &api.ResultSet{}
	if err := protojson.Unmarshal(data, set); err != nil {
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}
	return &Predicate{
		Data:   data,
		Parsed: set,
	}, nil
}

func (*Parser) SupportsType(predTypes ...string) bool {
	return slices.Contains(predTypes, string(PredicateType))
}
