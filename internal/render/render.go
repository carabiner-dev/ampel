// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"io"
	"sync"

	papi "github.com/carabiner-dev/policy/api/v1"

	"github.com/carabiner-dev/ampel/internal/drivers/attester"
	"github.com/carabiner-dev/ampel/internal/drivers/html"
	"github.com/carabiner-dev/ampel/internal/drivers/markdown"
	"github.com/carabiner-dev/ampel/internal/drivers/tty"
	"github.com/carabiner-dev/ampel/internal/drivers/vsa"
)

type driversList map[string]Driver

var (
	drivers = driversList{}
	drMtx   sync.Mutex
)

func LoadDefaultDrivers() {
	drMtx.Lock()
	drivers["attestation"] = attester.New()
	drivers["html"] = html.New()
	drivers["markdown"] = markdown.New()
	drivers["tty"] = tty.New()
	drivers["vsa"] = vsa.New()
	drMtx.Unlock()
}

func GetDriverBytType(t string) Driver {
	if d, ok := drivers[t]; ok {
		return d
	}
	return nil
}

func RegisterDriver(t string, driver Driver) {
	drMtx.Lock()
	drivers[t] = driver
	drMtx.Unlock()
}

func UnregisterDriver(t string, driver Driver) {
	drMtx.Lock()
	delete(drivers, t)
	drMtx.Unlock()
}

func NewEngine() *Engine {
	LoadDefaultDrivers()
	return &Engine{
		Driver: tty.New(),
	}
}

type Driver interface {
	RenderResultSet(w io.Writer, status *papi.ResultSet) error
	RenderResult(w io.Writer, status *papi.Result) error
}

type Engine struct {
	Driver Driver
}

// SetDriver sets the ourput driver format
func (e *Engine) SetDriver(format string) error {
	d := GetDriverBytType(format)
	if d == nil {
		return fmt.Errorf("no rendering driver for format %q", format)
	}
	e.Driver = d
	return nil
}

// RenderResultSet calls the method of the same name of the configured driver
func (e *Engine) RenderResultSet(w io.Writer, rset *papi.ResultSet) error {
	return e.Driver.RenderResultSet(w, rset)
}

// RenderResult calls the method of the same name of the configured driver
func (e *Engine) RenderResult(w io.Writer, result *papi.Result) error {
	return e.Driver.RenderResult(w, result)
}
