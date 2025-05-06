// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package trivy

import (
	"time"

	"github.com/carabiner-dev/ampel/pkg/attestation"
)

var PredicateType = attestation.PredicateType("https://trivy.dev/report")

type TrivyReport struct {
	SchemaVersion int        `json:"SchemaVersion"`
	CreatedAt     *time.Time `json:"CreatedAt"`
	ArtifactName  string     `json:"ArtifactName"`
	ArtifactType  string     `json:"ArtifactType"`

	Results []Result `json:"Results"`
}

type Result struct {
	Vulnerabilities []*Vulnerability `json:"Vulnerabilities"`
}

type CVSS struct {
	V3Vector string  `json:"V3Vector"`
	V3Score  float32 `json:"V3Score"`
}

type Vulnerability struct {
	VulnerabilityID  string            `json:"VulnerabilityID"`
	PkgName          string            `json:"PkgName"`
	InstalledVersion string            `json:"InstalledVersion"`
	FixedVersion     string            `json:"FixedVersion"`
	PkgIdentifier    map[string]string `json:"PkgIdentifier"`
	CVSS             map[string]CVSS   `json:"CVSS"`
	Title            string            `json:"Title"`
	Description      string            `json:"Description"`
	Severity         string            `json:"Severity"` // "CRITICAL"
	CweIDs           []string          `json:"CweIDs"`
	References       []string          `json:"References"`
	PublishedDate    *time.Time        `json:"PublishedDate"`
	LastModifiedDate *time.Time        `json:"LastModifiedDate"`
}
