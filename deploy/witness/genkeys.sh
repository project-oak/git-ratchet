#!/bin/bash
# Generate a witness Ed25519 key pair for git-ratchet deployment.
#
# Usage:
#   bazel run //deploy/witness:genkeys -- <output-dir>
#
# Creates:
#   <output-dir>/witness-key — witness private key file (cosigner)
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <output-dir>" >&2
    exit 1
fi

OUTDIR="$1"
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
NAME="git-ratchet-witness"
TYPE_HEX="04"  # Ed25519 cosigner
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
printf '%s\n%s\n' "$VKEY" "$SEED_B64" > "$OUTDIR/witness-key"
chmod 600 "$OUTDIR/witness-key"

echo "Witness key written to $OUTDIR/witness-key"
echo "  vkey: $VKEY"
