// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

// ToMap compiles the context data values into a map, filling the fields
// with their defaults when needed.
func (c *Context) ToMap() map[string]any {
	ret := map[string]any{}
	for label, value := range c.Values {
		if value.Value != nil {
			ret[label] = value.Value.AsInterface()
		} else {
			ret[label] = value.Default.AsInterface()
		}
	}
	return ret
}
