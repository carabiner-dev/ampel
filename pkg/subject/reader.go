// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package subject

import (
	"io"

	"github.com/carabiner-dev/attestation"
)

// SubjectMatter abstracts anything that con be converted to an attestation subject
// for now it is just an empty interface but we have a type in case we want to
// implement common methods.
type SubjectMatter interface{}

// Reader abstracts objects that can read a statement subject
// from a source and return an attestation.Subject struct
type Reader interface {
	Read(SubjectMatter) (attestation.Subject, error)
}

// FromPath is a convenience method to return a subject from a file.
func FromPath(path string) (attestation.Subject, error) {
	return NewFileReader().ReadPath(path)
}

// FromStream is a convenience method to return a subject from an io.Reader stream.
func FromStream(r io.Reader) (attestation.Subject, error) {
	return NewFileReader().ReadStream(r)
}
