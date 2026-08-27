#!/usr/bin/env bash
# Fetch the canonical AEP record schema from the published @wasmagent/protocol
# npm package, pinned by exact version + sha256 of the tarball.
#
# Per the org repository-boundary policy, shared schemas are NEVER vendored,
# inlined, or hand-copied into this repo; they are consumed from the published
# package. Bump VERSION (and SHA256) only via a new @wasmagent/protocol release.
#
# Usage: ci/fetch_aep_schema.sh [out-dir]
set -euo pipefail

VERSION="0.1.7"
SHA256="d29773ee3a5dbb5037ddb8831893236be8318fd53827bf55beaa051063f21b81"

OUT_DIR="${1:-target/schema}"
mkdir -p "$OUT_DIR"

TARBALL="$(mktemp -t wasmagent-protocol-tgz.XXXXXX)"
trap 'rm -f "$TARBALL"' EXIT

curl --proto '=https' --tlsv1.2 --silent --show-error --fail --location \
  "https://registry.npmjs.org/@wasmagent/protocol/-/protocol-${VERSION}.tgz" \
  -o "$TARBALL"

echo "${SHA256}  ${TARBALL}" | shasum -a 256 --check --status

tar -xzf "$TARBALL" -C "$OUT_DIR" \
  --strip-components=3 "package/schemas/aep/aep-record.schema.json"

echo "fetched @wasmagent/protocol@${VERSION} schema -> ${OUT_DIR}/aep-record.schema.json"
