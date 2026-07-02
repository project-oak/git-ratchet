# cosign

Offline witness cosigning tool — the standalone counterpart to the HTTP witness
server.

`cosign` reads a checkpoint request from a file, verifies the origin signature
and any required state transitions, and writes the cosignature line to stdout.

## Usage

```
cosign \
    --request <path> \
    --origin-vkeys <path> \
    --key <path> \
    [--stored-checkpoint <path>]
```

## Flags

| Flag | Required | Description |
|------|----------|-------------|
| `--request` | Yes | Path to the add-checkpoint request file. Uses the same wire format as the HTTP `POST /add-checkpoint` body: base64-encoded commit objects (ancestry proof), an empty line separator, then the signed checkpoint note. |
| `--origin-vkeys` | Yes | Path to a file containing trusted origin verifier keys, one per line. Blank lines and lines starting with `#` are ignored. |
| `--key` | Yes | Path to the witness private key file. The key file format is two lines: the verifier key (vkey) string, followed by the base64-encoded 32-byte seed. |
| `--stored-checkpoint` | No | Path to an existing cosigned checkpoint file. If provided, the cosign binary enforces state transitions (see below). If omitted, any request is accepted (first-checkpoint scenario). |

### State transition rules

When `--stored-checkpoint` is provided:

- **Branches** (`refs/heads/*`): the new commit must descend from the stored
  commit (ancestry proof required).
- **Tags** (`refs/tags/*`): the object hash must match the stored hash (tags are
  immutable).

## Building

```
bazel build //witness/cosign
```

## Example

Decomposed checkpoint workflow using `cosign`:

```bash
# 1. Origin produces the request.
git-ratchet checkpoint-request \
    --ref refs/heads/main \
    --key origin-key.pem \
    --output-request request.txt \
    --output-note note.txt

# 2. Witness cosigns.
cosign \
    --request request.txt \
    --origin-vkeys origins.txt \
    --key witness-key.pem \
    --stored-checkpoint stored.txt \
    > cosig.txt

# 3. Origin assembles and stores.
git-ratchet checkpoint-store \
    --ref refs/heads/main \
    --policy policy.txt \
    --note note.txt \
    --cosig cosig.txt
```
