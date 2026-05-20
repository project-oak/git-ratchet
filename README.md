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

A checkpoint is a [signed note](https://c2sp.org/signed-note) binding a repository ref to a commit hash, signed by the origin and cosigned by independent witnesses. See [docs/git-checkpoint.md](docs/git-checkpoint.md) for the full format specification.

## Ancestry proofs

For branch checkpoints, the witness does not need a full clone of the repository. The checkpoint request includes the chain of commit objects from the new commit back to the previously cosigned commit. Each commit object is self-authenticating (its hash covers its parent field), so the witness verifies the chain by hashing each object and confirming the parent linkage. For merge commits, only the parent on the path back to the old commit is needed.

Tag checkpoints do not require ancestry proofs. The witness simply checks that the submitted commit matches its stored state (or accepts the first checkpoint for a new tag).

## Witness policy

A policy specifies the trusted origin key, witness keys, and quorum. The format extends the C2SP [tlog-policy](https://github.com/C2SP/C2SP/blob/main/tlog-policy.md) specification with a `ref` directive for enumerating protected refs; see [docs/checkpoint-policy.md](docs/checkpoint-policy.md) for the full format.

## Usage

```
git-ratchet checkpoint --ref <refpath> --key <path> --policy <path> [flags]
git-ratchet verify --policy <path> [--ref <refpath>] [flags]
```

If `--ref` is omitted from `verify`, all refs listed in the policy are verified.

See `git-ratchet <command> --help` for details.

## Future work

### `git-ratchet audit`

git-ratchet's `verify` command checks that a checkpoint is properly signed and that the ref still matches, but it does not verify the integrity of the underlying Git object graph. Git itself only checks object hashes lazily (on read), meaning objects deep in the DAG that are never accessed are never verified. Additionally, Git's [replace refs](https://git-scm.com/docs/git-replace) mechanism allows transparent object substitution at the application layer — silently swapping out any commit, tree, or blob without changing the hashes that reference it.

A `git-ratchet audit` command could combine several checks into a single comprehensive integrity scan:

- **`git fsck`**: Walk the full object database and verify that every object's content matches its hash, all referenced objects exist, and the DAG is well-formed.
- **`git-ratchet verify`**: Verify all checkpoint refs against the witness policy.
- **Replace ref rejection**: Error if any refs exist under `refs/replace/`. Replace refs allow transparent object substitution — any commit, tree, or blob can be silently swapped for a different object without changing the hashes that reference it. This breaks the Merkle chain property that git-ratchet relies on: a checkpoint binds a ref to a commit hash, but replace refs can change the content served for that hash without invalidating the checkpoint. Since replace refs are not fetched by default (`git clone` and `git fetch` only transfer `refs/heads/*` and `refs/tags/*`), most repositories will not have them, and their presence should be treated as an integrity violation.

This would provide a stronger end-to-end integrity guarantee than any of these checks in isolation.

### Replace ref tracking (potential future extension)

Some repositories — particularly those with long histories stitched together from pre-Git version control systems — have legitimate replace refs (e.g. grafts from SVN migrations). For these repositories, a future extension could allow replace refs to coexist with git-ratchet by tracking them in a dedicated branch:

1. A branch (e.g. `_replace-log`) would contain a `replace-map` file listing every approved `<original-sha> <replacement-sha>` pair.
2. This branch would be checkpointed and witnessed like any other branch, using forward-only ratchet semantics. The full history of replace ref additions, modifications, and deletions would be preserved as commits on this branch.
3. `audit` would cross-reference the actual `refs/replace/*` state against the latest `replace-map`, erroring on any untracked, missing, or modified replace refs.
4. A `git-ratchet sync-replace` command would reconstruct local `refs/replace/*` from the tracking branch, sidestepping the fact that Git does not propagate replace refs by default.

This would keep the witness role simple (it just enforces forward-only on a branch), keep the audit trail in the Git DAG (not in witness state), and provide a clear onboarding path for legacy repositories.

## Building

Requires [Bazel](https://bazel.build/) 9.1+:

```
bazel build //:git-ratchet
```
