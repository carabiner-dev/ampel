// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package context

import "strings"

// StringMapList returns context data from a list of strings where each
// line has the value preceded by a colon and the value. For example:
//
//	"value1:My Value"
//	"OtherValue:Another value"
//	"Number:3" // This would be a string "3"
//
// All values returned by the provider are strings.
//
// This provider was created to support context strings passed in the CLI
// to the ampel verifier.
type StringMapList []string

func (sml *StringMapList) GetContextValue(key string) (any, error) {
	if sml == nil {
		return nil, nil
	}
	pref := key + ":"
	for _, s := range *sml {
		v, ok := strings.CutPrefix(s, pref)
		if ok {
			return v, nil
		}
	}
	return nil, nil
}

func (sml *StringMapList) GetContextMap(keys []string) (map[string]any, error) {
	if sml == nil {
		return nil, nil
	}
	ret := map[string]any{}
	for _, s := range *sml {
		k, v, _ := strings.Cut(s, ":")
		ret[k] = v
	}
	return ret, nil
}
