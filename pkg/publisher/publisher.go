// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package publisher defines the interface and registry for the AMPEL results
// publishers. A publisher emits the results of a policy evaluation to an
// external system: a webhook, a gRPC API, an eventing system, etc.
// For now, publishing is best effort: The AMPEL verifier calls the configured
// publishers once an evaluation completes but never queues, retries or fails
// an evaluation because a publisher returned an error. Any drivers that need
// a retry mechanism implement it themselves.
//
// Publishers are pluggable like other ampel subsystems. Each driver registers a
// builder under a driver id and is selected through an initstring of the form
// "driver:spec". The scheme picks the driver from the registry; the spec is
// interpreted into the configuration struct passed to the driver's Init method.
package publisher

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	papi "github.com/carabiner-dev/policy/api/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// Publisher is the interface implemented by all publisher drivers.
type Publisher interface {
	// Init configures the driver. The configuration struct is built by the
	// registry from the spec portion of the publisher's initstring.
	Init(*structpb.Struct) error

	// Publish emits the evaluation results. It is called once per evaluation
	// with the results of the verified policy material. The papi.Results
	// interface is satisfied by all of the material kinds the verifier can
	// produce (*papi.Result, *papi.ResultGroup and *papi.ResultSet). Publish is
	// best-effort: a returned error is logged by the verifier but never fails
	// the evaluation.
	Publish(context.Context, papi.Results, ...PublishOpt) error
}

// BuilderFunc returns a new, unconfigured instance of a driver.
type BuilderFunc func() Publisher

// PublishOpt is a functional option modifying a single Publish call.
type PublishOpt func(*PublishOptions)

// PublishOptions carries cross-driver options for a Publish call. It is
// currently empty but reserved so the Publish signature is stable as options
// are added.
type PublishOptions struct{}

var (
	registryMtx sync.RWMutex
	registry    = map[string]BuilderFunc{}
)

// Register adds a driver builder to the registry under its driver id. It is
// meant to be called from a driver package's init() function.
func Register(driver string, fn BuilderFunc) {
	registryMtx.Lock()
	defer registryMtx.Unlock()
	registry[driver] = fn
}

// New builds and initializes a single publisher from an initstring of the form
// "driver:spec". The scheme (everything before the first colon) selects the
// driver from the registry and the spec is interpreted into the configuration
// struct passed to the driver's Init method.
func New(initString string) (Publisher, error) {
	driver, spec, ok := strings.Cut(initString, ":")
	if !ok || driver == "" {
		return nil, fmt.Errorf("invalid publisher initstring %q (expected \"driver:spec\")", initString)
	}

	registryMtx.RLock()
	build, ok := registry[driver]
	registryMtx.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no publisher driver registered for %q", driver)
	}

	cfg, err := specToStruct(spec)
	if err != nil {
		return nil, fmt.Errorf("parsing %q publisher spec: %w", driver, err)
	}

	p := build()
	if err := p.Init(cfg); err != nil {
		return nil, fmt.Errorf("initializing %q publisher: %w", driver, err)
	}
	return p, nil
}

// NewSet builds a list of publishers from a list of initstrings. It fails on
// the first initstring that cannot be parsed or initialized.
func NewSet(initStrings []string) ([]Publisher, error) {
	pubs := make([]Publisher, 0, len(initStrings))
	for _, s := range initStrings {
		p, err := New(s)
		if err != nil {
			return nil, err
		}
		pubs = append(pubs, p)
	}
	return pubs, nil
}

// specToStruct interprets the spec portion of a publisher initstring into the
// configuration struct handed to a driver's Init method. The spec is parsed as
// URL query syntax (key=value&key=value). As a convenience, a non-empty spec
// that contains no "=" is stored whole under the "spec" key so simple drivers
// can take a bare value (eg "webhook:https://example.com/hook").
func specToStruct(spec string) (*structpb.Struct, error) {
	fields := map[string]any{}
	switch {
	case spec == "":
		// No configuration.
	case !strings.Contains(spec, "="):
		fields["spec"] = spec
	default:
		values, err := url.ParseQuery(spec)
		if err != nil {
			return nil, err
		}
		for k, v := range values {
			if len(v) == 1 {
				fields[k] = v[0]
				continue
			}
			anys := make([]any, len(v))
			for i := range v {
				anys[i] = v[i]
			}
			fields[k] = anys
		}
	}
	return structpb.NewStruct(fields)
}
