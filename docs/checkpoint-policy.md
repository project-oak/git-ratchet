# Git Checkpoint Policy

This document specifies the policy file format used by git-ratchet to verify Git ref checkpoints. The format extends the C2SP [tlog-policy][] specification with a `ref` directive for enumerating protected Git refs.

<!-- TODO: update tlog-policy link once https://github.com/C2SP/C2SP/pull/233 is merged -->
[tlog-policy]: https://github.com/C2SP/C2SP/pull/233
[signed-note]: https://c2sp.org/signed-note@v1.0.0
[checkpoint]: git-checkpoint.md

## Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC 8174][] when, and only when, they appear in all capitals, as shown here.

[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html

## Introduction

A git-ratchet checkpoint policy specifies the trust configuration for verifying [checkpoints][checkpoint] of Git refs. The policy identifies the log (origin) key, the set of trusted witnesses, the quorum rule, and — optionally — the set of refs that are expected to have valid checkpoints.

A policy file has two distinct consumers:

- **Log origins** use the policy when creating a checkpoint to discover witness endpoints and the required quorum. The ref to checkpoint is selected via the `--ref` CLI flag; `ref` directives in the policy are not consulted.
- **Verifiers** use the policy to verify checkpoint signatures and, when `ref` directives are present, to enumerate the full set of refs that must pass verification.

## Base format

The `log`, `witness`, `group`, and `quorum` directives follow the [tlog-policy][] specification exactly. Refer to that document for syntax, semantics, ordering rules, and character set constraints.

In summary:

- `log <vkey> [<url>]` — defines the origin (log) key. The vkey's key name is the log's origin line, which forms the first component of every checkpoint body.
- `witness <name> <vkey> [<url>]` or `witness <name> <url> <vkey>` — defines a trusted witness.
- `group <name> <k|any|all> <member>...` — defines a named threshold group of witnesses and/or sub-groups.
- `quorum <name|none>` — defines the cosignature quorum required for a checkpoint to be considered valid.

Blank lines and lines beginning with `#` (possibly preceded by whitespace) are ignored.

## The `ref` directive

A `ref` directive declares a Git ref that is expected to have a valid checkpoint. Zero or more `ref` directives MAY appear in a policy file. A policy used for verification MUST contain at least one `ref` directive.

```
ref <refpath>
```

The `<refpath>` MUST be a full Git ref path beginning with `refs/heads/` (for branches) or `refs/tags/` (for tags). Examples:

```
ref refs/heads/main
ref refs/tags/v1.0.0
ref refs/tags/v1.1.0
```

Duplicate `ref` directives (listing the same ref path more than once) are not allowed.

The `ref` directive MAY appear anywhere in the policy file relative to other directives. It does not interact with the `group` or `quorum` ordering constraints defined by tlog-policy.

### Semantics

The `ref` directive has no effect on checkpointing. When the origin creates a checkpoint, the ref is determined by the `--ref` CLI flag; `ref` directives in the policy are ignored.

For verification, `ref` directives define the complete set of refs that the verifier considers protected:

- **`verify --policy <path>` (no `--ref` flag):** The verifier MUST verify checkpoints for every ref listed in the policy. If the policy contains no `ref` directives, this is an error.

- **`verify --policy <path> --ref <refpath>`:** The verifier MUST verify the checkpoint for the specified ref only. The specified ref MUST match a `ref` directive in the policy; if it does not, verification MUST fail.

## Checkpoint body format

The checkpoint body format is defined in [git-checkpoint.md](git-checkpoint.md). The origin string in the checkpoint body is the key name from the `log` directive's vkey — this is how the policy connects the origin key to the checkpoints it signs.

## Example policy

A verifier policy for a repository with one protected branch and two protected tags:

```
log example-origin+a1b2c3d4+<base64 public key>

ref refs/heads/main
ref refs/tags/v1.0.0
ref refs/tags/v1.1.0

witness w1 https://witness1.example.com witness1+e5f6a7b8+<base64 public key>
witness w2 https://witness2.example.com witness2+c9d0e1f2+<base64 public key>

group all-witnesses all w1 w2
quorum all-witnesses
```

A policy used by the origin when checkpointing (no `ref` directives needed):

```
log example-origin+a1b2c3d4+<base64 public key>

witness w1 https://witness1.example.com witness1+e5f6a7b8+<base64 public key>
witness w2 https://witness2.example.com witness2+c9d0e1f2+<base64 public key>

group all-witnesses all w1 w2
quorum all-witnesses
```

## Ref kind derivation

The ref kind (branch or tag) is derived from the ref path prefix:

- `refs/heads/*` → branch semantics (forward-only ratchet)
- `refs/tags/*` → tag semantics (immutable pin)

This derivation applies uniformly: in the policy's `ref` directives, in the `--ref` CLI flag, and in the first line of the checkpoint body. There is no separate mechanism for specifying the ref kind.
