# cosign

The witness half of a [GitHub Issue witness](../../docs/github-issue-witness.md).

`cosign` answers one [tlog-witness][] `add-checkpoint` request delivered as a
file rather than as a POST, and writes the response to stdout. Both are
[`message/http`][RFC 9112]: an issue carries the request and a comment carries
the response, in place of a POST and its reply.

Behind the transport it runs [transparency-dev/witness][]'s own
`add-checkpoint` handler, so it answers exactly as an HTTP witness would —
same status codes, same bodies. Only the wire differs.

## Usage

```
cosign \
    --request <path> \
    --origin-vkeys <path> \
    --key <path> \
    --stored-checkpoint <path>
```

## Flags

| Flag | Required | Description |
|------|----------|-------------|
| `--request` | Yes | Path to the `message/http` request: an HTTP request message targeting `/add-checkpoint`, whose body is the [tlog-witness][] add-checkpoint body — the old tree size, a consistency proof, and the signed checkpoint note. |
| `--origin-vkeys` | Yes | Path to a file of trusted origin verifier keys, one per line. Blank lines and lines starting with `#` are ignored. A checkpoint from an origin not listed here is answered as an unknown log. |
| `--key` | Yes | Path to the witness private key file, in the [signed-note] private key encoding (`PRIVATE+KEY+<name>+<key hash>+<base64>`), as written by `genkey`. |
| `--stored-checkpoint` | Yes | Path to this witness's stored checkpoint for the origin. A witness with no state cannot ratchet, so this is required; the file need not exist yet, and is written when a submission is accepted. |

## What it enforces

The ratchet here is over the log's tree size, not over any one ref. The witness
checks that the submitted checkpoint is signed by a trusted origin and that its
tree is consistent with — an append-only extension of — the tree it last
cosigned for that origin. It cannot tell a fast-forward from a rollback, and is
not asked to: see
[Security properties](../../docs/transparency-log.md#security-properties).

A submission the witness declines is still an answer the origin needs, so a
refusal is a response to return, not an error to swallow.

## Building

```
bazel build //witness/cosign
```

## Example

Given the `http` block from an issue body in `request.txt`:

```bash
cosign \
    --request request.txt \
    --origin-vkeys "origins/github.com/example/repo" \
    --key witness.key \
    --stored-checkpoint "checkpoints/github.com/example/repo" \
    > response.txt
```

`response.txt` goes back as a comment on the issue, and the updated
`--stored-checkpoint` file is committed. The
[`cosign` action](../../actions/cosign) does all of this; running the binary by
hand is for reproducing what a witness answered.

[signed-note]: https://c2sp.org/signed-note@v1.0.0
[tlog-witness]: https://c2sp.org/tlog-witness
[RFC 9112]: https://www.rfc-editor.org/rfc/rfc9112.html
[transparency-dev/witness]: https://github.com/transparency-dev/witness
