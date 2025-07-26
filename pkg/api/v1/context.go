// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

type ContextMap map[string]any

// Merge merges the values set in cv2 into cv. If values are not set nothing
// is replaced
func (cv *ContextVal) Merge(cv2 *ContextVal) {
	if v := cv2.Default; v != nil {
		cv.Default = v
	}
	if v := cv2.Value; v != nil {
		cv.Value = v
	}
	if v := cv2.Required; v != nil {
		cv.Required = v
	}
}

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
