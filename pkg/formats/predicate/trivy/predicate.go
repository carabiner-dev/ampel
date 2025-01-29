// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package trivy

import (
	"time"

	"github.com/puerco/ampel/pkg/attestation"
)

var PredicateType = attestation.PredicateType("https://trivy.dev/report")

type TrivyReport struct {
	SchemaVersion int
	CreatedAt     *time.Time
	ArtifactName  string
	ArtifactType  string

	Results []Result
}

type Result struct {
	Vulnerabilities []*Vulnerability
}

type CVSS struct {
	V3Vector string
	V3Score  float32
}

type Vulnerability struct {
	VulnerabilityID  string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	PkgIdentifier    map[string]string
	CVSS             map[string]CVSS
	Title            string
	Description      string
	Severity         string // "CRITICAL"
	CweIDs           []string
	References       []string
	PublishedDate    *time.Time
	LastModifiedDate *time.Time
}
