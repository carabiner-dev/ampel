// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attester

import (
	"io"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/verifier"
)

func New() *Driver {
	v, _ := verifier.New()
	return &Driver{
		Ampel: v,
	}
}

type Driver struct {
	Ampel *verifier.Ampel
}

func (d *Driver) RenderResultSet(w io.Writer, rset *api.ResultSet) error {
	return d.Ampel.AttestResultSet(w, rset)
}

func (d *Driver) RenderResult(w io.Writer, status *api.Result) error {
	return d.Ampel.AttestResult(w, status)
}
