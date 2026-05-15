# git-ratchet

Rollback-resistant Git branch checkpointing.

git-ratchet creates **witnessed checkpoints** for Git branches, ensuring that branch history can only move forward. Independent witnesses cosign checkpoints, making silent rollback (via force-push, reset, or rebase) detectable and — with a quorum of witnesses — effectively impossible.

## How it works

Git is tamper-evident (commits reference their parents by hash), but it is not append-only. A repository owner can force-push to remove commits from a branch, and there is no cryptographic evidence they ever existed.

git-ratchet closes this gap:

1. **Checkpoint**: After a push (or merge) to a protected branch, `git-ratchet checkpoint` creates a checkpoint — a [signed note](https://c2sp.org/signed-note) binding a branch to a commit hash, signed with the origin's private key. It submits this checkpoint, along with an ancestry proof, to one or more independent **witnesses**.

2. **Witness cosigning**: Each witness verifies the origin signature, then checks that the new commit is a descendant of the last commit it cosigned for that origin. If valid, it returns a [cosignature](https://c2sp.org/tlog-cosignature). The witness stores the new commit hash, enforcing a forward-only ratchet. If the origin ever submits a checkpoint for a commit that does not descend from the previous one, the witness refuses.

3. **Storage**: The cosigned checkpoint (origin signature + witness cosignatures) is stored as a Git reference at `refs/checkpoints/<branch>`.

4. **Verification**: Anyone can run `git-ratchet verify` to fetch the checkpoint ref, verify the origin and witness signatures against a policy, and confirm the branch tip matches the checkpointed commit.

## Checkpoint format

A checkpoint is a [C2SP signed note](https://c2sp.org/signed-note) with a structured body identifying the repository and branch:

```
github.com/example/repo refs/heads/main
4f0f30afb02b71590f0b2e0a67f0b846715e1d04

— example-origin+a1b2c3d4 <base64 signature>
— witness1+e5f6a7b8 <base64 cosignature>
— witness2+c9d0e1f2 <base64 cosignature>
```

The first line is the **origin** — a string identifying the repository and branch. The second line is the commit hash. The signatures follow the [signed-note](https://c2sp.org/signed-note) format: the origin signs the checkpoint, and witnesses append cosignatures.

The origin is identified by a [verifier key](https://c2sp.org/signed-note) (vkey):

```
example-origin+a1b2c3d4+<base64 public key>
```

This key is configured in the witness (so the witness knows which origins it serves) and in the verifier policy (so verifiers know which origin key to trust).

## Ancestry proofs

The witness does not need a full clone of the repository. The checkpoint request includes the chain of commit objects from the new commit back to the previously cosigned commit. Each commit object is self-authenticating (its hash covers its parent field), so the witness verifies the chain by hashing each object and confirming the parent linkage. For merge commits, only the parent on the path back to the old commit is needed.

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
git-ratchet checkpoint [flags]
git-ratchet verify [flags]
```

See `git-ratchet <command> --help` for details.

## Building

Requires [Bazel](https://bazel.build/) 9.1+:

```
bazel build //:git-ratchet
```
