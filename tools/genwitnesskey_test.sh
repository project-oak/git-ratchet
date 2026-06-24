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

# Test for genwitnesskey: verifies output format and key structure.
set -euo pipefail

# The genwitnesskey binary path is passed as the first argument by Bazel.
GENWITNESSKEY="$1"
if [ ! -x "$GENWITNESSKEY" ]; then
  echo "FAIL: genwitnesskey binary not found at $GENWITNESSKEY"
  exit 1
fi

OUTDIR=$(mktemp -d)
trap 'rm -rf "$OUTDIR"' EXIT

# Run the generator.
"$GENWITNESSKEY" "$OUTDIR" test-witness

KEYFILE="$OUTDIR/witness-key"

# Check the key file exists.
if [ ! -f "$KEYFILE" ]; then
  echo "FAIL: key file not created"
  exit 1
fi

# Check it has exactly 2 lines.
LINES=$(wc -l < "$KEYFILE")
if [ "$LINES" -ne 2 ]; then
  echo "FAIL: expected 2 lines, got $LINES"
  exit 1
fi

# Check the vkey format: name+hexhash+base64data
VKEY=$(sed -n '1p' "$KEYFILE")
if ! echo "$VKEY" | grep -qE '^test-witness\+[0-9a-f]{8}\+.+$'; then
  echo "FAIL: vkey format invalid: $VKEY"
  exit 1
fi

# Extract and check the type byte (should be 0x04 for Ed25519 cosigner).
B64_DATA=$(printf '%s' "$VKEY" | sed 's/^[^+]*+[^+]*+//')
TYPE_BYTE=$(printf '%s' "$B64_DATA" | base64 -d | od -An -tx1 -N1 | tr -d ' ')
if [ "$TYPE_BYTE" != "04" ]; then
  echo "FAIL: expected type byte 04 (Ed25519 cosigner), got $TYPE_BYTE"
  exit 1
fi

# Check the base64 data decodes to 33 bytes (1 type byte + 32 pubkey).
DATA_LEN=$(printf '%s' "$B64_DATA" | base64 -d | wc -c)
if [ "$DATA_LEN" -ne 33 ]; then
  echo "FAIL: expected 33 bytes of vkey data, got $DATA_LEN"
  exit 1
fi

# Check the seed (line 2) decodes to 32 bytes.
SEED_B64=$(sed -n '2p' "$KEYFILE")
SEED_LEN=$(printf '%s' "$SEED_B64" | base64 -d | wc -c)
if [ "$SEED_LEN" -ne 32 ]; then
  echo "FAIL: expected 32-byte seed, got $SEED_LEN"
  exit 1
fi

# Check the file permissions are 600.
PERMS=$(stat -c '%a' "$KEYFILE")
if [ "$PERMS" != "600" ]; then
  echo "FAIL: expected permissions 600, got $PERMS"
  exit 1
fi

echo "PASS: genwitnesskey"
