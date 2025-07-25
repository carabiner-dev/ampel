// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

// ContextMap compiles the context data values into a map, filling the fields
// with their defaults when needed.
func (s *PolicySet) ContextMap() map[string]any {
	ret := map[string]any{}
	for label, value := range s.GetCommon().GetContext() {
		if value.Value != nil {
			ret[label] = value.Value.AsInterface()
		} else {
			ret[label] = value.Default.AsInterface()
		}
	}
	return ret
}

// ContextMap compiles the context data values into a map, filling the fields
// with their defaults when needed.
func (c *Policy) ContextMap() map[string]any {
	ret := map[string]any{}
	for label, value := range c.Context {
		if value.Value != nil {
			ret[label] = value.Value.AsInterface()
		} else {
			ret[label] = value.Default.AsInterface()
		}
	}
	return ret
}
