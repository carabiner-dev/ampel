// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package subject

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	gointoto "github.com/in-toto/attestation/go/v1"

	"github.com/puerco/ampel/pkg/attestation"
)

func NewFileReader() *FileReader {
	return &FileReader{
		Options: defaultFileReaderOptions,
	}
}

type FileReader struct {
	Options FileReaderOptions
}

type FileReaderOptions struct {
	Hashers map[string]hash.Hash
}

var defaultFileReaderOptions = FileReaderOptions{
	Hashers: map[string]hash.Hash{
		"sha1":   sha1.New(),
		"sha256": sha256.New(),
		"sha512": sha512.New(),
	},
}

func (fr *FileReader) Reader(s SubjectMatter) (attestation.Subject, error) {
	if s == nil {
		return nil, fmt.Errorf("empty input to subject reader")
	}
	switch val := s.(type) {
	case string:
		return fr.ReadPath(val)
	default:
		if rdr, ok := s.(io.Reader); ok {
			return fr.ReadStream(rdr)
		}
	}
	return nil, fmt.Errorf("subject reader received unknown input")
}

// ReadPath returns a subject by reading a path
func (fr *FileReader) ReadPath(path string) (attestation.Subject, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening path: %w", err)
	}

	defer f.Close()

	sub, err := fr.ReadStream(f)
	if err != nil {
		return nil, err
	}

	sub.(*gointoto.ResourceDescriptor).Name = path
	return sub, nil
}

// ReadStream creates a resource descriptor from a reader stream
func (fr *FileReader) ReadStream(r io.Reader) (attestation.Subject, error) {
	var hashes = map[string]string{}
	var errs = []error{}
	for algo, fn := range fr.Options.Hashers {
		fn.Reset()
		if _, err := io.Copy(fn, r); err != nil {
			errs = append(errs, fmt.Errorf("hashing input with %s: %w", algo, err))
		}
		hashes[algo] = hex.EncodeToString(fn.Sum(nil))
	}
	return &gointoto.ResourceDescriptor{
		Digest: hashes,
	}, errors.Join(errs...)
}
