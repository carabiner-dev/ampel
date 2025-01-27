#!/usr/bin/env bash
# 
# This script refreshes the SLSA protos from the latest versions in 
# the SLSA repository.

set -e

TMP_DIR=$(mktemp -d )

git clone --depth=1 git@github.com:slsa-framework/slsa.git "$TMP_DIR"

cp "${TMP_DIR}/docs/spec/v1.0/schema/provenance.proto" proto/slsa/provenance-v1.0.proto
cp "${TMP_DIR}/docs/spec/v1.1/schema/provenance.proto" proto/slsa/provenance-v1.1.proto

rm -rf "$TMP_DIR"
