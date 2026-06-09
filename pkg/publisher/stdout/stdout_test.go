// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package stdout

import (
	"bytes"
	"context"
	"testing"

	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/ampel/pkg/publisher"
)

func TestRegistered(t *testing.T) {
	t.Parallel()
	p, err := publisher.New(DriverName + ":")
	require.NoError(t, err)
	require.IsType(t, &Publisher{}, p)
}

func TestPublish(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	p := &Publisher{Writer: &buf}

	rs := &papi.ResultSet{
		PolicySet: &papi.PolicyRef{Id: "test-set"},
		Status:    papi.StatusPASS,
	}
	require.NoError(t, p.Publish(context.Background(), rs))
	require.Contains(t, buf.String(), "test-set")
}
