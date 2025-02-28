// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"io"

	"github.com/carabiner-dev/ampel/internal/drivers/tty"
	api "github.com/carabiner-dev/ampel/pkg/api/v1"
)

func NewEngine() *Engine {
	return &Engine{
		Driver: tty.New(),
	}
}

type Driver interface {
	RenderResultSet(w io.Writer, status *api.ResultSet) error
	RenderResult(w io.Writer, status *api.Result) error
}

type Engine struct {
	Driver Driver
}

// RenderResultSet calls the method of the same name of the configured driver
func (e *Engine) RenderResultSet(w io.Writer, rset *api.ResultSet) error {
	return e.Driver.RenderResultSet(w, rset)
}

// RenderResult calls the method of the same name of the configured driver
func (e *Engine) RenderResult(w io.Writer, result *api.Result) error {
	return e.Driver.RenderResult(w, result)
}
