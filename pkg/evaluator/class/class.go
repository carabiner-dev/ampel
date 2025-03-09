// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package class

import "strings"

// Class is a label that describes an evaluator class
type Class string

func (c *Class) Version() string {
	_, a, _ := strings.Cut(string(*c), "@")
	return a
}

func (c *Class) Name() string {
	b, _, _ := strings.Cut(string(*c), "@")
	return b
}
