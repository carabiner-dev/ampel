package oscal

import (
	"encoding/json"
	"fmt"
	"os"
)

type Reader struct {
}

func (p *Reader) Parse(path string) (*Catalog, error) {
	var catalog = &Catalog{}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parsing data: %w", err)
	}
	if err := json.Unmarshal(data, catalog); err != nil {
		return nil, fmt.Errorf("parsing oscal catalog: %w", err)
	}
	return catalog, nil
}
