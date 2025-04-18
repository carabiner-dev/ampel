// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package trivy

import (
	"time"

	"github.com/carabiner-dev/ampel/pkg/attestation"
)

var PredicateType = attestation.PredicateType("https://trivy.dev/report")

type TrivyReport struct {
	SchemaVersion int        `json:"schema_version"`
	CreatedAt     *time.Time `json:"created_at"`
	ArtifactName  string     `json:"artifact_name"`
	ArtifactType  string     `json:"artifact_type"`

	Results []Result `json:"results"`
}

type Result struct {
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
}

type CVSS struct {
	V3Vector string  `json:"v3_vector"`
	V3Score  float32 `json:"v3_score"`
}

type Vulnerability struct {
	VulnerabilityID  string            `json:"vulnerability_id"`
	PkgName          string            `json:"pkg_name"`
	InstalledVersion string            `json:"installed_version"`
	FixedVersion     string            `json:"fixed_version"`
	PkgIdentifier    map[string]string `json:"pkg_identifier"`
	CVSS             map[string]CVSS   `json:"cvss"`
	Title            string            `json:"title"`
	Description      string            `json:"description"`
	Severity         string            `json:"severity"` // "CRITICAL"
	CweIDs           []string          `json:"cwe_ids"`
	References       []string          `json:"references"`
	PublishedDate    *time.Time        `json:"published_date"`
	LastModifiedDate *time.Time        `json:"last_modified_date"`
}
