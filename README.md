# git-ratchet

Protect your releases and branch history from silent rollback, force-push, and tag tampering — with cryptographic proof that anyone can verify.

By [Ben Birt](https://github.com/benbirt) · Licensed under the [Apache License 2.0](LICENSE)

git-ratchet creates **witnessed checkpoints** for Git branches and tags, ensuring that branch history can only move forward and that tags remain immutable. Independent witnesses cosign checkpoints, making silent rollback (via force-push, reset, or rebase) and tag tampering detectable and — with a quorum of witnesses — effectively impossible.

> git-ratchet [uses itself to protect its own `main` branch and release tags](#self-witnessing).

## How it works

Git is tamper-evident (commits reference their parents by hash), but it is not append-only. A repository owner can force-push to remove commits from a branch, or silently move a tag to point at a different commit. There is no cryptographic evidence the original state ever existed.

git-ratchet closes this gap:

1. **Checkpoint**: After a push (or merge) to a protected branch, or when creating a release tag, `git-ratchet checkpoint` creates a checkpoint — a [signed note](https://c2sp.org/signed-note) binding a ref to an object hash, signed with the origin's Ed25519 private key. It submits this checkpoint, along with an ancestry proof (for branches), to one or more independent **witnesses**.

2. **Witness cosigning**: Each witness verifies the origin signature, then enforces ref-type-specific rules (see [docs/witness-protocol.md](docs/witness-protocol.md) for the full protocol specification):
   - **Branches** (`refs/heads/*`): The witness checks that the new commit is a descendant of the last commit it cosigned for that origin. If valid, it returns a [cosignature](https://c2sp.org/tlog-cosignature). This enforces a forward-only ratchet — if the origin ever submits a checkpoint for a commit that does not descend from the previous one, the witness refuses.
   - **Tags** (`refs/tags/*`): The witness checks that the object hash matches the one it previously stored. Tags are immutable: once a tag is witnessed, it is pinned to that object hash forever. Any attempt to checkpoint a moved tag is rejected. For annotated tags, the pinned hash is the tag object hash (not the underlying commit hash).

3. **Storage**: The cosigned checkpoint (origin signature + witness cosignatures) is stored as a Git reference at `refs/checkpoints/heads/<branch>` or `refs/checkpoints/tags/<tag>`.

4. **Verification**: Anyone can run `git-ratchet verify` to fetch the checkpoint ref, verify the origin and witness signatures against a policy, and confirm the ref has not moved ahead of the checkpointed commit (branches must be at or behind the checkpoint; tags must match exactly).

## Checkpoint format

A checkpoint is a [signed note](https://c2sp.org/signed-note) binding a repository ref to an object hash, signed by the origin and cosigned by independent witnesses. See [docs/git-checkpoint.md](docs/git-checkpoint.md) for the full format specification.

## Ancestry proofs

For branch checkpoints, the witness does not need a full clone of the repository. The checkpoint request includes the chain of commit objects from the new commit back to the previously cosigned commit. Each commit object is self-authenticating (its hash covers its parent field), so the witness verifies the chain by hashing each object and confirming the parent linkage. For merge commits, only the parent on the path back to the old commit is needed.

Tag checkpoints do not require ancestry proofs. The witness simply checks that the submitted commit matches its stored state (or accepts the first checkpoint for a new tag).

## Witness policy
A policy specifies the trusted origin key, witness keys, and quorum. The format follows the [C2SP](https://c2sp.org/) [tlog-policy](https://c2sp.org/tlog-policy) specification, extended with the `github-issue://` witness URI scheme for [GitHub Issue witnesses](docs/github-issue-witness.md).

## Checkpoint modes

git-ratchet supports two checkpoint formats, selected with `--mode`.

| | `git-checkpoint` (default) | `tlog` |
|---|---|---|
| What is stored | A signed note per ref, at `refs/checkpoints/*` | A Merkle transparency log of ref updates, at `refs/ratchet/log` |
| What the witness checks | Git commit ancestry | Merkle tree consistency |
| Witness protocol | [git-ratchet's own](docs/witness-protocol.md) | C2SP [tlog-witness](https://c2sp.org/tlog-witness) |
| Witness implementation | git-ratchet provides one | Any on the existing network |
| A rollback is refused by | The witness, at cosigning time | `verify`, at verification time |
| `verify` does | O(1): checks one signed note | O(entries for the ref): walks the log |

Both modes give the same guarantee, and in both the relying party establishes it by running `verify`. What differs is where the ratchet is enforced, and so how much work `verify` has to do.

In `git-checkpoint` mode the witness has already checked ancestry, so `verify` need only check a signed note. The cost is a bespoke witness protocol: an operator can only witness a git-ratchet repository by running git-ratchet's own witness.

In `tlog` mode the checkpoint is a standard [tlog-checkpoint](https://c2sp.org/tlog-checkpoint) with no Git-specific fields, so any witness on the existing network can cosign it. The witness cannot tell a fast-forward from a rollback, so `verify` establishes ancestry itself by walking the logged entries — a local walk, since the log is contained by the repository.

`log` and `checkpoint` also refuse to record a rewrite. That is there to keep an operator from destroying a ref by accident, not to stop an attacker: anyone who can write to the log ref can push entries without going near those commands.

See [docs/tlog-variant.md](docs/tlog-variant.md) for the full specification and a comparison of the two modes.

In `tlog` mode, recording a ref and checkpointing the log are separate steps:
`log` grows the log locally, and `checkpoint` gets whatever the log holds
cosigned by the policy's witnesses. One checkpoint covers any number of logged
refs.

```bash
git-ratchet log        --mode tlog --ref refs/heads/main --ref refs/tags/v1.0.0
git-ratchet checkpoint --mode tlog --key origin.key --policy policy.txt
git-ratchet verify     --mode tlog --ref refs/heads/main --policy policy.txt
```

## Witnesses

git-ratchet supports two types of witnesses, both reached by `checkpoint` itself:

- **HTTP witnesses**: A standalone server (deployed e.g. on Cloud Run) that responds to the [witness HTTP protocol](docs/witness-protocol.md). See [deploy/witness/README.md](deploy/witness/README.md) for deployment.
- **GitHub Issue witnesses**: A GitHub repository that cosigns checkpoints via GitHub Actions, using GitHub Issues as the transport (`tlog` mode only). See [docs/github-issue-witness.md](docs/github-issue-witness.md) for setup.

## GitHub Actions

Composite actions are provided for CI/CD integration:

| Action | Description |
|--------|-------------|
| [`actions/setup`](actions/setup) | Install `git-ratchet` or `cosign` from a GitHub Release |
| [`actions/checkpoint`](actions/checkpoint) | Origin-side: create, submit, assemble, and push a checkpoint |
| [`actions/cosign`](actions/cosign) | Witness-side: cosign a checkpoint request from a GitHub Issue |

See each action's README for inputs, permissions, and example workflows.

## Usage

### `git-ratchet checkpoint`

```
git-ratchet checkpoint --ref <refpath> --key <path> --policy <path> [--origin <name>] [flags]
```

Signs a checkpoint for the ref, submits it to the witnesses in the policy file, collects cosignatures, and stores the cosigned checkpoint as a Git ref (`refs/checkpoints/heads/<branch>` or `refs/checkpoints/tags/<tag>`).

In `git-checkpoint` mode, witnesses are reached over HTTP only; a policy naming a `github-issue://` witness is rejected. In `tlog` mode both are reached directly, with `--github-token` supplying the token a GitHub Issue witness needs.

### `git-ratchet verify`

```
git-ratchet verify --policy <path> --ref <refpath> [--ref <refpath>...] [flags]
```

Verifies checkpoint signatures against the policy and confirms each ref still matches the checkpointed commit. The `--ref` flag can be repeated to verify multiple refs.

In `--mode tlog` this additionally walks the logged entries for each ref, checking that branch history only ever moved forward and that no tag was ever logged at a second object. See [Checkpoint modes](#checkpoint-modes).

Every git invocation passes `--no-replace-objects`, so refs under `refs/replace/` cannot substitute one object's content for another's during verification. What is checkpointed is the true object graph, and that is the graph verification reads.

### `cosign` (standalone binary)

```
cosign \
    --request <path> \
    --origin-vkeys <path> \
    --key <path> \
    --stored-checkpoint <path>
```

A standalone witness binary (built via `bazel build //witness/cosign`) that reads an `add-checkpoint` request from a file and writes the witness's response to stdout, both as `message/http`. It is what a [GitHub Issue witness](docs/github-issue-witness.md) runs: the same protocol an HTTP witness serves, carried by an issue and a comment rather than a POST.

See `git-ratchet <command> --help` for details.

## Future work

### Replace ref tracking (potential future extension)

Some repositories — particularly those with long histories stitched together from pre-Git version control systems — have legitimate replace refs (e.g. grafts from SVN migrations). For these repositories, a future extension could allow replace refs to coexist with git-ratchet by tracking them in a dedicated branch:

1. A branch (e.g. `_replace-log`) would contain a `replace-map` file listing every approved `<original-sha> <replacement-sha>` pair.
2. This branch would be checkpointed and witnessed like any other branch, using forward-only ratchet semantics. The full history of replace ref additions, modifications, and deletions would be preserved as commits on this branch.
3. `verify` would cross-reference the actual `refs/replace/*` state against the latest `replace-map`, erroring on any untracked, missing, or modified replace refs, and read through the approved ones rather than ignoring them as it does today.
4. A `git-ratchet sync-replace` command would reconstruct local `refs/replace/*` from the tracking branch, sidestepping the fact that Git does not propagate replace refs by default.

This would keep the witness role simple (it just enforces forward-only on a branch), keep the record in the Git DAG (not in witness state), and provide a clear onboarding path for legacy repositories.

## Building

Requires [Bazel](https://bazel.build/) 9.1+:

```
bazel build //:git-ratchet
bazel build //witness/cosign
```

## Demo

This section walks through the full end-to-end setup: provisioning an origin signing key, deploying a witness, writing a policy, and then checkpointing and verifying a repository.

### 1. Provision an origin signing key

Follow [deploy/origin/README.md](deploy/origin/README.md) to create a GCP Cloud KMS Ed25519 signing key for your origin. At the end you will have:

- A `--kms-key` resource name to pass to `git-ratchet checkpoint`.
- An **origin name** — the key name portion of the vkey (e.g. `git-ratchet-origin`). Pass this as `--origin` when checkpointing with `--kms-key`.
- An **origin vkey** printed by `kmsvkey` — a string of the form `git-ratchet-origin+<keyid>+<base64pubkey>`. Keep this; you'll need it in the policy.

### 2. Deploy a witness

Follow [deploy/witness/README.md](deploy/witness/README.md) to deploy the witness to GCP Cloud Run. At the end you will have:

- A **witness URL** (e.g. `https://git-ratchet-witness-<hash>-uc.a.run.app`).
- A **witness vkey** printed by `kmsvkey` — a string of the form `git-ratchet-witness+<keyid>+<base64pubkey>`.

### 3. Write a policy file

Create a `policy.txt` (not committed) that ties together the origin vkey and the witness:

```
log <origin-vkey>

witness w1 <witness-url> <witness-vkey>

quorum w1
```

For example:

```
log git-ratchet-origin+a1b2c3d4+AAAA...

witness w1 https://git-ratchet-witness-xxxxxxxx-uc.a.run.app git-ratchet-witness+e5f6a7b8+BBBB...

quorum w1
```

### 4. Checkpoint and verify

You can either build the binary once and run it directly, or use `bazel run` to build-and-run in a single step.

**Checkpoint** a branch (after a push):

```bash
bazel run //:git-ratchet -- checkpoint \
  --ref refs/heads/main \
  --kms-key "$KMS_KEY" \
  --origin "$ORIGIN" \
  --policy $PWD/policy.txt
```

To inspect the stored checkpoint:

```bash
git cat-file -p refs/checkpoints/heads/main
```

**Verify** that a ref still matches its witnessed checkpoint:

```bash
bazel run //:git-ratchet -- verify --policy $PWD/policy.txt --ref refs/heads/main
```

Alternatively, build the binary once and invoke it directly:

```bash
bazel build //:git-ratchet
./bazel-bin/git-ratchet_/git-ratchet checkpoint --ref refs/heads/main --kms-key "$KMS_KEY" --origin "$ORIGIN" --policy $PWD/policy.txt
./bazel-bin/git-ratchet_/git-ratchet verify --policy $PWD/policy.txt --ref refs/heads/main
```

## Self-witnessing

git-ratchet uses itself to protect its own `main` branch and release tags. Every push to `main` and every `v*` tag triggers the [checkpoint workflow](.github/workflows/checkpoint.yml), which submits the checkpoint to a witness at [`BenBirt/git-witness`](https://github.com/BenBirt/git-witness).

The witness policy is in [`ratchet-checkpoint.policy`](ratchet-checkpoint.policy). Anyone can verify the integrity of this repository:

```bash
git fetch origin 'refs/ratchet/log:refs/ratchet/log'
git-ratchet verify --mode tlog --policy ratchet-checkpoint.policy --ref refs/heads/main
```

## Disclaimer

This is not an officially supported Google product. This project is not
eligible for the [Google Open Source Software Vulnerability Rewards
Program](https://bughunters.google.com/open-source-security).
