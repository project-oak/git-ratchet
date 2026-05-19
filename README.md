# git-ratchet

Rollback-resistant Git ref checkpointing.

git-ratchet creates **witnessed checkpoints** for Git branches and tags, ensuring that branch history can only move forward and that tags remain immutable. Independent witnesses cosign checkpoints, making silent rollback (via force-push, reset, or rebase) and tag tampering detectable and — with a quorum of witnesses — effectively impossible.

## How it works

Git is tamper-evident (commits reference their parents by hash), but it is not append-only. A repository owner can force-push to remove commits from a branch, or silently move a tag to point at a different commit. There is no cryptographic evidence the original state ever existed.

git-ratchet closes this gap:

1. **Checkpoint**: After a push (or merge) to a protected branch, or when creating a release tag, `git-ratchet checkpoint` creates a checkpoint — a [signed note](https://c2sp.org/signed-note) binding a ref to a commit hash, signed with the origin's private key. It submits this checkpoint, along with an ancestry proof (for branches), to one or more independent **witnesses**.

2. **Witness cosigning**: Each witness verifies the origin signature, then enforces ref-type-specific rules:
   - **Branches** (`refs/heads/*`): The witness checks that the new commit is a descendant of the last commit it cosigned for that origin. If valid, it returns a [cosignature](https://c2sp.org/tlog-cosignature). This enforces a forward-only ratchet — if the origin ever submits a checkpoint for a commit that does not descend from the previous one, the witness refuses.
   - **Tags** (`refs/tags/*`): The witness checks that the commit matches the one it previously stored. Tags are immutable: once a tag is witnessed, it is pinned to that commit forever. Any attempt to checkpoint a moved tag is rejected.

3. **Storage**: The cosigned checkpoint (origin signature + witness cosignatures) is stored as a Git reference at `refs/checkpoints/heads/<branch>` or `refs/checkpoints/tags/<tag>`.

4. **Verification**: Anyone can run `git-ratchet verify` to fetch the checkpoint ref, verify the origin and witness signatures against a policy, and confirm the ref still points to the checkpointed commit.

## Checkpoint format

A checkpoint is a [C2SP signed note](https://c2sp.org/signed-note) with a structured body identifying the repository and ref:

```
github.com/example/repo refs/heads/main
4f0f30afb02b71590f0b2e0a67f0b846715e1d04

— example-origin+a1b2c3d4 <base64 signature>
— witness1+e5f6a7b8 <base64 cosignature>
— witness2+c9d0e1f2 <base64 cosignature>
```

The first line is the **origin** — a string identifying the repository and ref. The second line is the commit hash. The signatures follow the [signed-note](https://c2sp.org/signed-note) format: the origin signs the checkpoint, and witnesses append cosignatures.

Tag checkpoints use the same format with a tag ref:

```
github.com/example/repo refs/tags/v1.2.3
4f0f30afb02b71590f0b2e0a67f0b846715e1d04

— example-origin+a1b2c3d4 <base64 signature>
— witness1+e5f6a7b8 <base64 cosignature>
```

The origin is identified by a [verifier key](https://c2sp.org/signed-note) (vkey):

```
example-origin+a1b2c3d4+<base64 public key>
```

This key is configured in the witness (so the witness knows which origins it serves) and in the verifier policy (so verifiers know which origin key to trust).

## Ancestry proofs

For branch checkpoints, the witness does not need a full clone of the repository. The checkpoint request includes the chain of commit objects from the new commit back to the previously cosigned commit. Each commit object is self-authenticating (its hash covers its parent field), so the witness verifies the chain by hashing each object and confirming the parent linkage. For merge commits, only the parent on the path back to the old commit is needed.

Tag checkpoints do not require ancestry proofs. The witness simply checks that the submitted commit matches its stored state (or accepts the first checkpoint for a new tag).

## Hash function support

Git repositories use either SHA-1 or SHA-256 as their object hash, controlled by `extensions.objectFormat`. git-ratchet handles both transparently: the hash algorithm is inferred from the length of the commit ID in the checkpoint (40 hex characters → SHA-1, 64 → SHA-256). Ancestry proofs are verified using the same algorithm. No configuration is required — git-ratchet will work correctly with whichever object format the repository uses.

Note: SHA-256 repositories require Git ≥ 2.29 and are not yet widely supported by hosting platforms. git-ratchet's SHA-256 support is tested synthetically (with constructed commit objects) rather than against live SHA-256 repositories.

## Witness policy

A verifier's policy specifies the trusted origin key, witness keys, and quorum:

```
origin example-origin+a1b2c3d4+<base64 public key>
witness witness1+e5f6a7b8+<base64 public key>
witness witness2+c9d0e1f2+<base64 public key>
quorum 2
```

Verification succeeds only if the checkpoint carries a valid origin signature and valid cosignatures from at least `quorum` witnesses listed in the policy.

## Usage

```
git-ratchet checkpoint --branch <name> [flags]
git-ratchet checkpoint --tag <name> [flags]
git-ratchet verify --branch <name> [flags]
git-ratchet verify --tag <name> [flags]
```

See `git-ratchet <command> --help` for details.

## Future work

### `git-ratchet audit`

git-ratchet's `verify` command checks that a checkpoint is properly signed and that the ref still matches, but it does not verify the integrity of the underlying Git object graph. Git itself only checks object hashes lazily (on read), meaning objects deep in the DAG that are never accessed are never verified. Additionally, Git's [replace refs](https://git-scm.com/docs/git-replace) mechanism allows transparent object substitution at the application layer — silently swapping out any commit, tree, or blob without changing the hashes that reference it.

A `git-ratchet audit` command could combine several checks into a single comprehensive integrity scan:

- **`git fsck`**: Walk the full object database and verify that every object's content matches its hash, all referenced objects exist, and the DAG is well-formed.
- **`git-ratchet verify`**: Verify all checkpoint refs against the witness policy.
- **Replace ref detection**: Check for the existence of any refs under `refs/replace/` and loudly warn if found, since replace refs break the Merkle chain assumptions that git-ratchet relies on.

This would provide a stronger end-to-end integrity guarantee than any of these checks in isolation.

### Policy structure and naming

The policy file currently uses C2SP [tlog-policy](https://c2sp.org/tlog-policy) conventions: a `log` directive names the origin, and witnesses are listed with their verifier keys. The log name (e.g., `github.com/example/repo`) is a free-form string that must match the first line of every checkpoint, but there is no formal relationship between it and the Git remote URL, repository name, or the specific branch or tag being protected.

This creates an awkward gap: a single policy covers one "log" (origin key), but git-ratchet operates on individual refs within a repository. Questions to resolve include:

- Should the policy be scoped to a repository, or to individual refs? A policy-per-ref would allow different witness quorums for `main` vs. release tags, but adds configuration overhead.
- Should the log name be derived from the Git remote URL, or remain an opaque identifier? Deriving it reduces misconfiguration but ties the policy to hosting infrastructure.
- Should the policy file live in the repository itself (discoverable, versioned) or out-of-band (harder to tamper with, but less convenient)?

If the policy encodes the full ref (e.g., `github.com/example/repo refs/heads/main`), the `--branch` and `--tag` flags on `verify` become redundant — the ref path and its kind can be derived from the policy's log name. This would simplify the verify CLI to just `git-ratchet verify --policy <path>`.

### Post-quantum signatures (ML-DSA-44)

The C2SP [tlog-cosignature](https://c2sp.org/tlog-cosignature) specification defines ML-DSA-44 cosignatures (type byte `0x06`), and [tlog-checkpoint](https://c2sp.org/tlog-checkpoint) permits origins to use ML-DSA-44 signatures as well. Adding ML-DSA-44 support would require generalising the `Signer` type to handle different key material sizes and separating the wire type byte from the key role, since ML-DSA-44 uses `0x06` for both origins and cosigners (unlike Ed25519, which uses `0x01` and `0x04` respectively). See the `TODO(ML-DSA-44)` in `internal/note/note.go` for implementation notes.

## Building

Requires [Bazel](https://bazel.build/) 9.1+:

```
bazel build //:git-ratchet
```
