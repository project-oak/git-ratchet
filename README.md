# git-ratchet

Protect your releases and branch history from silent rollback, force-push, and tag tampering — with cryptographic proof that anyone can verify.

By [Ben Birt](https://github.com/benbirt) · Licensed under the [Apache License 2.0](LICENSE)

git-ratchet creates **witnessed checkpoints** for Git branches and tags, ensuring that branch history can only move forward and that tags remain immutable. Independent witnesses cosign checkpoints, making silent rollback (via force-push, reset, or rebase) and tag tampering detectable and — with a quorum of witnesses — effectively impossible.

## How it works

Git is tamper-evident (commits reference their parents by hash), but it is not append-only. A repository owner can force-push to remove commits from a branch, or silently move a tag to point at a different commit. There is no cryptographic evidence the original state ever existed.

git-ratchet closes this gap:

1. **Checkpoint**: After a push (or merge) to a protected branch, or when creating a release tag, `git-ratchet checkpoint` creates a checkpoint — a [signed note](https://c2sp.org/signed-note) binding a ref to a commit hash, signed with the origin's private key. It submits this checkpoint, along with an ancestry proof (for branches), to one or more independent **witnesses**.

2. **Witness cosigning**: Each witness verifies the origin signature, then enforces ref-type-specific rules (see [docs/witness-protocol.md](docs/witness-protocol.md) for the full protocol specification):
   - **Branches** (`refs/heads/*`): The witness checks that the new commit is a descendant of the last commit it cosigned for that origin. If valid, it returns a [cosignature](https://c2sp.org/tlog-cosignature). This enforces a forward-only ratchet — if the origin ever submits a checkpoint for a commit that does not descend from the previous one, the witness refuses.
   - **Tags** (`refs/tags/*`): The witness checks that the commit matches the one it previously stored. Tags are immutable: once a tag is witnessed, it is pinned to that commit forever. Any attempt to checkpoint a moved tag is rejected.

3. **Storage**: The cosigned checkpoint (origin signature + witness cosignatures) is stored as a Git reference at `refs/checkpoints/heads/<branch>` or `refs/checkpoints/tags/<tag>`.

4. **Verification**: Anyone can run `git-ratchet verify` to fetch the checkpoint ref, verify the origin and witness signatures against a policy, and confirm the ref has not moved ahead of the checkpointed commit (branches must be at or behind the checkpoint; tags must match exactly).

## Checkpoint format

A checkpoint is a [signed note](https://c2sp.org/signed-note) binding a repository ref to a commit hash, signed by the origin and cosigned by independent witnesses. See [docs/git-checkpoint.md](docs/git-checkpoint.md) for the full format specification.

## Ancestry proofs

For branch checkpoints, the witness does not need a full clone of the repository. The checkpoint request includes the chain of commit objects from the new commit back to the previously cosigned commit. Each commit object is self-authenticating (its hash covers its parent field), so the witness verifies the chain by hashing each object and confirming the parent linkage. For merge commits, only the parent on the path back to the old commit is needed.

Tag checkpoints do not require ancestry proofs. The witness simply checks that the submitted commit matches its stored state (or accepts the first checkpoint for a new tag).

## Witness policy

<!-- TODO: update tlog-policy link once https://github.com/C2SP/C2SP/pull/233 is merged -->
A policy specifies the trusted origin key, witness keys, and quorum. The format extends the C2SP [tlog-policy](https://github.com/C2SP/C2SP/pull/233) specification with a `ref` directive for enumerating protected refs; see [docs/checkpoint-policy.md](docs/checkpoint-policy.md) for the full format.

## Usage

### `git-ratchet checkpoint`

```
git-ratchet checkpoint --ref <refpath> --key <path> --policy <path> [flags]
```

Signs a checkpoint for the ref, submits it to the witnesses in the policy file, collects cosignatures, and stores the cosigned checkpoint as a Git ref (`refs/checkpoints/heads/<branch>` or `refs/checkpoints/tags/<tag>`).

Witnesses with non-HTTP endpoints (e.g. `github-issue://`) are skipped with a warning. Use the decomposed workflow below for those witnesses.

### `git-ratchet checkpoint-request`

```
git-ratchet checkpoint-request \
    --ref <refpath> \
    --key <path> \
    --output-request <path> \
    --output-note <path> \
    [--origin <name>] [flags]
```

Produces the add-checkpoint request body (ancestry proof + signed note) without contacting any witnesses. The output can later be submitted to witnesses out-of-band. The origin identity is derived from the key file; use `--origin` to override (required when using `--kms-key`).

### `git-ratchet checkpoint-store`

```
git-ratchet checkpoint-store \
    --ref <refpath> \
    --policy <path> \
    --note <path> \
    [--cosig <path>]... [flags]
```

Assembles a cosigned checkpoint from the signed note (produced by `checkpoint-request`) and one or more cosignature files (collected out-of-band), verifies the result against the policy, and stores it. The `--cosig` flag can be repeated for each witness cosignature.

### `git-ratchet verify`

```
git-ratchet verify --policy <path> [--ref <refpath>] [flags]
```

Verifies checkpoint signatures against the policy and confirms each ref still matches the checkpointed commit. If `--ref` is omitted, all refs listed in the policy are verified.

### `git-ratchet audit`

```
git-ratchet audit --policy <path> [flags]
```

Runs a comprehensive end-to-end integrity scan combining three checks:

1. **`git fsck`**: Walks the full object database and verifies that every object's content matches its hash, all referenced objects exist, and the DAG is well-formed.
2. **`git-ratchet verify`**: Verifies all checkpoint refs against the witness policy.
3. **Replace ref rejection**: Errors if any refs exist under `refs/replace/`. Replace refs allow transparent object substitution — any commit, tree, or blob can be silently swapped for a different object without changing the hashes that reference it. This breaks the Merkle chain property that git-ratchet relies on. Since replace refs are not fetched by default, their presence is treated as an integrity violation.

### `witness-cosign` (standalone binary)

```
witness-cosign \
    --request <path> \
    --origin-vkeys <path> \
    --key <path> \
    [--stored-checkpoint <path>]
```

A standalone witness binary (built via `bazel build //witness:cosign`) that reads an add-checkpoint request from a file, verifies the origin signature and ancestry proof, and writes the cosignature line to stdout. This is the offline counterpart to the HTTP witness server — it performs the same verification but reads from files instead of receiving HTTP requests.

### Decomposed workflow

The `checkpoint` command handles the full lifecycle for HTTP witnesses. For non-HTTP witnesses (e.g. GitHub Issues), use the decomposed workflow:

```bash
# 1. Produce the request and signed note
git-ratchet checkpoint-request \
    --ref refs/heads/main \
    --key origin-key.pem \
    --output-request request.txt \
    --output-note note.txt

# 2. Submit to each witness (e.g. via the standalone cosign binary)
witness-cosign \
    --request request.txt \
    --origin-vkeys origins.txt \
    --key witness-key.pem > cosig1.txt

# 3. Assemble and store the cosigned checkpoint
git-ratchet checkpoint-store \
    --ref refs/heads/main \
    --policy policy.txt \
    --note note.txt \
    --cosig cosig1.txt
```

See `git-ratchet <command> --help` for details.

## Future work

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
bazel build //witness:cosign
```

## Demo

This section walks through the full end-to-end setup: provisioning an origin signing key, deploying a witness, writing a policy, and then checkpointing, verifying, and auditing a repository.

### 1. Provision an origin signing key

Follow [deploy/origin/README.md](deploy/origin/README.md) to create a GCP Cloud KMS Ed25519 signing key for your origin. At the end you will have:

- A `--kms-key` resource name to pass to `git-ratchet checkpoint`.
- An **origin vkey** printed by `kmsvkey` — a string of the form `git-ratchet-origin+<keyid>+<base64pubkey>`. Keep this; you'll need it in the policy.

### 2. Deploy a witness

Follow [deploy/witness/README.md](deploy/witness/README.md) to deploy the witness to GCP Cloud Run. At the end you will have:

- A **witness URL** (e.g. `https://git-ratchet-witness-<hash>-uc.a.run.app`).
- A **witness vkey** printed by `kmsvkey` — a string of the form `git-ratchet-witness+<keyid>+<base64pubkey>`.

### 3. Write a policy file

Create a `policy.txt` (not committed) that ties together the origin vkey, the protected refs, and the witness:

```
log <origin-vkey>

ref refs/heads/main

witness w1 <witness-url> <witness-vkey>

quorum w1
```

For example:

```
log git-ratchet-origin+a1b2c3d4+AAAA...

ref refs/heads/main
ref refs/tags/v*

witness w1 https://git-ratchet-witness-xxxxxxxx-uc.a.run.app git-ratchet-witness+e5f6a7b8+BBBB...

quorum w1
```

See [docs/checkpoint-policy.md](docs/checkpoint-policy.md) for the full policy format.

### 4. Checkpoint, verify, and audit

You can either build the binary once and run it directly, or use `bazel run` to build-and-run in a single step.

**Checkpoint** a branch (after a push):

```bash
bazel run //:git-ratchet -- checkpoint \
  --ref refs/heads/main \
  --kms-key "$KMS_KEY" \
  --policy $PWD/policy.txt
```

To inspect the stored checkpoint:

```bash
git cat-file -p refs/checkpoints/heads/main
```

**Verify** that all refs in the policy still match their witnessed checkpoints:

```bash
bazel run //:git-ratchet -- verify --policy $PWD/policy.txt
```

Or verify a single ref:

```bash
bazel run //:git-ratchet -- verify --policy $PWD/policy.txt --ref refs/heads/main
```

**Audit** the full repository integrity (fsck + verify + replace-ref check):

```bash
bazel run //:git-ratchet -- audit --policy $PWD/policy.txt
```

Alternatively, build the binary once and invoke it directly:

```bash
bazel build //:git-ratchet
./bazel-bin/git-ratchet_/git-ratchet checkpoint --ref refs/heads/main --kms-key "$KMS_KEY" --policy $PWD/policy.txt
./bazel-bin/git-ratchet_/git-ratchet verify --policy $PWD/policy.txt
./bazel-bin/git-ratchet_/git-ratchet audit --policy $PWD/policy.txt
```

## Disclaimer

This is not an officially supported Google product. This project is not
eligible for the [Google Open Source Software Vulnerability Rewards
Program](https://bughunters.google.com/open-source-security).
