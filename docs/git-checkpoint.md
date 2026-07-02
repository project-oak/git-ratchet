# Git Checkpoint

This document specifies the format of a Git ref checkpoint: a [signed note][signed-note] binding a repository ref to the hash of the object it points to, cosigned by independent witnesses.

[signed-note]: https://c2sp.org/signed-note@v1.0.0
[tlog-cosignature]: https://c2sp.org/tlog-cosignature

## Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC 8174][] when, and only when, they appear in all capitals, as shown here.

[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html

## Checkpoint body

A checkpoint is a [signed note][signed-note]. The body consists of exactly two lines, each terminated by a newline (U+000A):

```
<origin> <refpath>
<object-hash>
```

The first line combines the **origin** — an opaque string identifying the repository — with the full **ref path**, separated by a single space (U+0020). The ref path MUST begin with `refs/heads/` (for branches) or `refs/tags/` (for tags).

The second line is the hex-encoded hash of the object the ref points to. For branches and lightweight tags this is a commit hash; for annotated tags this is the tag object hash.

## Origin

The origin is the key name from the origin's [verifier key][signed-note] (vkey):

```
<origin>+<key-hash>+<base64 public key>
```

For example, the vkey `github.com/example/repo+a1b2c3d4+<base64 public key>` has origin `github.com/example/repo`.

The origin is a fixed, canonical identifier for the repository. It is not derived from Git remote URLs at runtime.

## Signatures

The checkpoint is signed by the origin and cosigned by zero or more witnesses. The origin signs the checkpoint body following the [signed note][signed-note] format. Witnesses append [cosignatures][tlog-cosignature]:

```
<origin> <refpath>
<object-hash>

— <origin-name>+<key-hash> <base64 signature>
— <witness-name>+<key-hash> <base64 cosignature>
```

## Hash function support

Git repositories use either SHA-1 or SHA-256 as their object hash (`extensions.objectFormat`). The hash algorithm is inferred from the length of the object hash in the checkpoint body:

- 40 hex characters → SHA-1
- 64 hex characters → SHA-256

Implementations MUST accept both lengths. No explicit hash algorithm field is included in the checkpoint.

Note: SHA-256 repositories require Git ≥ 2.29 and are not yet widely supported by hosting platforms.

## Ref kind

The ref kind (branch or tag) is derived from the ref path prefix:

- `refs/heads/*` → branch (forward-only ratchet)
- `refs/tags/*` → tag (immutable pin)

The semantics of each ref kind — how witnesses verify state transitions — are defined in the [witness protocol](witness-protocol.md).

## Examples

A branch checkpoint with two witness cosignatures:

```
github.com/example/repo refs/heads/main
4f0f30afb02b71590f0b2e0a67f0b846715e1d04

— example-origin+a1b2c3d4 <base64 signature>
— witness1+e5f6a7b8 <base64 cosignature>
— witness2+c9d0e1f2 <base64 cosignature>
```

A tag checkpoint:

```
github.com/example/repo refs/tags/v1.2.3
4f0f30afb02b71590f0b2e0a67f0b846715e1d04

— example-origin+a1b2c3d4 <base64 signature>
— witness1+e5f6a7b8 <base64 cosignature>
```
