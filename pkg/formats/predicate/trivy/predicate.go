package trivy

import "time"

type Predicate struct {
	Parsed *TrivyReport
	Data   []byte
}

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

type CVSS map[string]any

type Vulnerability struct {
	VulnerabilityID string
	PkgIdentifier   map[string]string
	CVSS            map[string]CVSS
	Title           string
	Description     string
	Severity        string // "CRITICAL"
	CweIDs          []string
	References      []string
	PublishedDate   *time.Time
}
