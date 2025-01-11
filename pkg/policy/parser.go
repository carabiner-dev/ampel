package policy

import (
	"fmt"
	"os"

	v1 "github.com/puerco/ampel/pkg/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func NewParser() *Parser {
	return &Parser{}
}

type Parser struct {
}

// ParseFile parses a policy file
func (p *Parser) ParseFile(path string) (*v1.PolicySet, error) {
	// TODO(puerco): Support policies enclosed in envelopes
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading polciy file: %w", err)
	}

	return p.ParseSet(data)
}

func (p *Parser) ParseSet(policySetData []byte) (*v1.PolicySet, error) {
	var set = v1.PolicySet{}
	// dec := json.NewDecoder(bytes.NewReader(policySetData))

	if err := protojson.Unmarshal(policySetData, &set); err != nil {
		return nil, fmt.Errorf("parsing policy source: %w", err)
	}
	return &set, nil
}
