#!/bin/bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Generate an origin Ed25519 key pair for git-ratchet.
#
# Usage:
#   bazel run //tools:genoriginkey -- <output-dir> [name]
#
# Creates:
#   <output-dir>/origin-key — origin private key file (Ed25519 origin, type 0x01)
#
# The vkey (verifier key) is printed to stdout. Add it to the witness's
# origins file so the witness will accept checkpoints signed by this key.
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: $0 <output-dir> [name]" >&2
    echo "" >&2
    echo "  output-dir   Directory to write the origin-key file into" >&2
    echo "  name         Key name (default: git-ratchet-origin)" >&2
    exit 1
fi

OUTDIR="$1"
NAME="${2:-git-ratchet-origin}"

# When invoked via `bazel run`, relative paths resolve against the runfiles
# sandbox, not the caller's working directory. Use BUILD_WORKSPACE_DIRECTORY
# (set by Bazel) to resolve relative paths against the workspace root.
if [[ "$OUTDIR" != /* ]] && [ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]; then
    OUTDIR="${BUILD_WORKSPACE_DIRECTORY}/${OUTDIR}"
fi

mkdir -p "$OUTDIR"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Generate Ed25519 private key in DER (PKCS#8) format.
openssl genpkey -algorithm ed25519 -outform DER > "$TMPDIR/priv.der"

# Extract 32-byte seed (offset 16 in PKCS#8 DER).
dd if="$TMPDIR/priv.der" bs=1 skip=16 count=32 2>/dev/null > "$TMPDIR/seed"

# Derive public key and extract raw 32 bytes (offset 12 in SubjectPublicKeyInfo DER).
openssl pkey -inform DER -in "$TMPDIR/priv.der" -pubout -outform DER 2>/dev/null > "$TMPDIR/pub.der"
dd if="$TMPDIR/pub.der" bs=1 skip=12 count=32 2>/dev/null > "$TMPDIR/pubkey"

# Key hash: SHA-256(name || "\n" || type_byte || pubkey)[:4], as 8 hex chars.
TYPE_HEX="01"  # Ed25519 origin
KEYHASH=$(
    { printf '%s\n' "$NAME"; printf "\\x${TYPE_HEX}"; cat "$TMPDIR/pubkey"; } \
    | sha256sum | head -c 8
)

# vkey = name+hexID+base64(typeByte || pubkey)
VKEY_DATA_B64=$(
    { printf "\\x${TYPE_HEX}"; cat "$TMPDIR/pubkey"; } | base64 -w 0
)
VKEY="${NAME}+${KEYHASH}+${VKEY_DATA_B64}"

# Seed as base64.
SEED_B64=$(base64 -w 0 < "$TMPDIR/seed")

# Write key file.
KEYFILE="$OUTDIR/origin-key"
printf '%s\n%s\n' "$VKEY" "$SEED_B64" > "$KEYFILE"
chmod 600 "$KEYFILE"

echo "Origin key written to $KEYFILE"
echo "  vkey: $VKEY"
echo ""
echo "Add the vkey to your witness's origins file so it will accept"
echo "checkpoints signed with this key."
