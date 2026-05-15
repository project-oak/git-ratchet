# git-ratchet

Rollback-resistant Git branch checkpointing.

git-ratchet creates **witnessed checkpoints** for Git branches, ensuring that branch history can only move forward. Independent witnesses cosign checkpoints, making silent rollback (via force-push, reset, or rebase) detectable and — with a quorum of witnesses — effectively impossible.

## How it works

Git is tamper-evident (commits reference their parents by hash), but it is not append-only. A repository owner can force-push to remove commits from a branch, and there is no cryptographic evidence they ever existed.

git-ratchet closes this gap:

1. **Checkpoint**: After a push (or merge) to a protected branch, `git-ratchet checkpoint` creates a signed statement binding the branch name to a commit hash. It submits this checkpoint — along with an ancestry proof — to one or more independent **witnesses**.

2. **Witness cosigning**: Each witness verifies that the new commit is a descendant of the last commit it cosigned for that branch, then returns a cosignature. The witness stores the new commit hash, enforcing a forward-only ratchet. If the repo owner ever tries to checkpoint a commit that does not descend from the previous one, the witness refuses.

3. **Storage**: The cosigned checkpoint (owner signature + witness cosignatures) is stored as a Git reference at `refs/checkpoints/<branch>`.

4. **Verification**: Anyone can run `git-ratchet verify` to fetch the checkpoint ref, verify the signatures against a witness policy, and confirm the branch tip matches the checkpointed commit.

## Ancestry proofs

The witness does not need a full clone of the repository. The checkpoint request includes the chain of commit objects from the new commit back to the previously cosigned commit. Each commit object is self-authenticating (its hash covers its parent field), so the witness verifies the chain by hashing each object and confirming the parent linkage. For merge commits, only the parent on the path back to the old commit is needed.

## Witness policy

A witness policy specifies the trusted witnesses and quorum requirements:

```
repo github.com/example/repo
witness witness1.example.com witness1+def456+<key>
witness witness2.example.com witness2+ghi789+<key>
quorum 2
```

Verification succeeds only if the checkpoint carries valid cosignatures from at least `quorum` witnesses listed in the policy.

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
