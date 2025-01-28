#!/usr/bin/env bash
# 
# This script refreshes the SLSA protos from the latest versions in 
# the SLSA repository.

set -e

TMP_DIR=$(mktemp -d )

git clone --depth=1 https://github.com/slsa-framework/slsa.git "$TMP_DIR"

cp "${TMP_DIR}/docs/spec/v1.0/schema/provenance.proto" proto/slsa/v10/provenance.proto
cp "${TMP_DIR}/docs/spec/v1.1/schema/provenance.proto" proto/slsa/v11/provenance.proto

sed -ie 's/syntax = "proto3";/syntax = "proto3";\noption go_package = "github.com\/puerco\/ampel\/pkg\/formats\/predicate\/slsa\/provenance\/v10";/' proto/slsa/v10/provenance.proto
sed -ie 's/syntax = "proto3";/syntax = "proto3";\noption go_package = "github.com\/puerco\/ampel\/pkg\/formats\/predicate\/slsa\/provenance\/v11";/' proto/slsa/v11/provenance.proto

rm -rf "$TMP_DIR"
