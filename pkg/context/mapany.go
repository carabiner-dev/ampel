// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// MapAnyProvider adds the Provider interface functions on top of a standard map
// the idea is that anything that can provide a map[string]any can create a
// provider very easy.
type MapAnyProvider map[string]any

// NewProviderFromJSON returns a new context provider from JSON data
// ingested from a reader.
//
// The data can't be just any JSON though, it needs to be able to be
// parsed to a map[string]any.
func NewProviderFromJSON(r io.Reader) (Provider, error) {
	ret := &MapAnyProvider{}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(ret); err != nil {
		return nil, fmt.Errorf("unmarshaling context data: %w", err)
	}
	return ret, nil
}

func NewProviderFromJSONFile(path string) (Provider, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening json file: %w", err)
	}
	return NewProviderFromJSON(f)
}

func (mapr *MapAnyProvider) GetContextValue(key string) (any, error) {
	if mapr == nil {
		return nil, nil
	}
	if v, ok := (*mapr)[key]; ok {
		return v, nil
	}
	return nil, nil
}

func (mapr *MapAnyProvider) GetContextMap(keys []string) (map[string]any, error) {
	ret := map[string]any{}
	for _, k := range keys {
		if v, ok := (*mapr)[k]; ok {
			ret[k] = v
		}
	}

	return ret, nil
}
