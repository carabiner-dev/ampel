// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package stdout implements a mock publisher that writes the evaluation results
// as JSON to a writer (os.Stdout by default). It is mainly useful for tests and
// for manually inspecting what would be published.
package stdout

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	papi "github.com/carabiner-dev/policy/api/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/carabiner-dev/ampel/pkg/publisher"
)

// DriverName is the id used to select this publisher in an initstring.
const DriverName = "stdout"

func init() {
	publisher.Register(DriverName, func() publisher.Publisher { return New() })
}

// Publisher writes the result set as indented JSON to Writer.
type Publisher struct {
	Writer io.Writer
}

// New returns a stdout publisher writing to os.Stdout.
func New() *Publisher {
	return &Publisher{Writer: os.Stdout}
}

// Init takes no configuration.
func (p *Publisher) Init(*structpb.Struct) error { return nil }

// Publish writes the results to the configured writer as indented JSON.
func (p *Publisher) Publish(_ context.Context, results papi.Results, _ ...publisher.PublishOpt) error {
	w := p.Writer
	if w == nil {
		w = os.Stdout
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling results: %w", err)
	}
	if _, err := fmt.Fprintln(w, string(data)); err != nil {
		return fmt.Errorf("writing results: %w", err)
	}
	return nil
}
