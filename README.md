# git-ratchet

Protect your releases and branch history from silent rollback, force-push, and tag tampering — with cryptographic proof that anyone can verify.

By [Ben Birt](https://github.com/benbirt) · Licensed under the [Apache License 2.0](LICENSE)

git-ratchet keeps a **transparency log** of a repository's ref updates, cosigned by independent witnesses. Branch history moving backwards (via force-push, reset, or rebase) or a tag moving at all is then caught by verification rather than passing silently — and once a rollback has been recorded and cosigned, it cannot be removed from the log without every witness's cosignature failing to check out.

> git-ratchet [uses itself to protect its own `main` branch and release tags](#self-witnessing).

## How it works

Git is tamper-evident (commits reference their parents by hash), but it is not append-only. A repository owner can force-push to remove commits from a branch, or silently move a tag to point at a different commit. There is no cryptographic evidence the original state ever existed.

git-ratchet closes this gap by keeping a **transparency log** of the repository's own ref updates, inside the repository:

1. **Log**: After a push to a protected branch, or when creating a release tag, `git-ratchet log --ref` appends an entry recording the object that ref points at. This is local: no key, and no witnesses are contacted. The log lives at `refs/ratchet/log`.

2. **Checkpoint**: `git-ratchet checkpoint` signs the log's head as a [tlog-checkpoint](https://c2sp.org/tlog-checkpoint) — an origin, a tree size and a Merkle root hash — and submits it to the **witnesses** named in the policy. Each returns a [cosignature](https://c2sp.org/tlog-cosignature) attesting that the log only ever grew by appending. One checkpoint covers every ref logged so far.

3. **Storage**: The cosigned checkpoint is stored in the log ref itself, so the whole record travels with the repository.

4. **Verification**: Anyone can run `git-ratchet verify` to check the checkpoint's signatures against a policy and then walk the logged entries for a ref, confirming that a branch only ever moved forward and that a tag never moved at all.

The checkpoint carries no Git-specific fields, so **any witness implementing [tlog-witness](https://c2sp.org/tlog-witness) can cosign one** without knowing what Git is. That matters because the security of a ratchet rests on witness diversity, and a bespoke witness protocol is an obstacle to it.

The consequence is that a witness cannot tell a fast-forward from a rollback — it sees only tree heads. It does not need to. What it attests is that the log is append-only, which is what makes a rollback, once recorded, permanent and undeniable. `verify` is where a rollback is caught, by a local walk over entries the repository already contains.

See [docs/transparency-log.md](docs/transparency-log.md) for the full specification.

## Witness policy

A policy specifies the trusted origin key, witness keys, and quorum. The format follows the [C2SP](https://c2sp.org/) [tlog-policy](https://c2sp.org/tlog-policy) specification, extended with the `github-issue://` witness URI scheme for [GitHub Issue witnesses](docs/github-issue-witness.md).

## Logging and checkpointing

Recording a ref and checkpointing the log are disjoint operations. `log` grows the log locally; `checkpoint` gets whatever the log holds cosigned by the policy's witnesses. One checkpoint covers any number of logged refs.

```bash
git-ratchet log        --ref refs/heads/main --ref refs/tags/v1.0.0
git-ratchet checkpoint --key origin.key --policy policy.txt
git-ratchet verify     --ref refs/heads/main --policy policy.txt
```

Keeping them separate means a witness that is down, slow, or refusing cannot cost the repository a log entry: the entry is already recorded, and the next checkpoint covers it.

`log` and `checkpoint` also refuse to record a rewrite. That is there to keep an operator from destroying a ref by accident, not to stop an attacker: anyone who can write to the log ref can push entries without going near those commands.

## Witnesses

Any [tlog-witness](https://c2sp.org/tlog-witness) implementation can cosign a git-ratchet checkpoint. `checkpoint` reaches every witness in the policy itself, whatever carries it:

- **HTTP witnesses**: any witness on the existing network, reached by a POST.
- **GitHub Issue witnesses**: a GitHub repository that cosigns via GitHub Actions, with an issue carrying the request and a comment carrying the reply. No server to deploy. See [docs/github-issue-witness.md](docs/github-issue-witness.md) for setup.

## GitHub Actions

Composite actions are provided for CI/CD integration:

| Action | Description |
|--------|-------------|
| [`actions/setup`](actions/setup) | Install `git-ratchet` or `cosign` from a GitHub Release |
| [`actions/log`](actions/log) | Origin-side: record a ref in the log and push the entry |
| [`actions/checkpoint`](actions/checkpoint) | Origin-side: checkpoint the log, collect cosignatures, push the result |
| [`actions/cosign`](actions/cosign) | Witness-side: cosign a checkpoint request from a GitHub Issue |

See each action's README for inputs, permissions, and example workflows.

## Usage

### `git-ratchet log`

```
git-ratchet log --ref <refpath> [--ref <refpath>...] [flags]
```

Records each ref's current object in the repository's transparency log. This is the only command that grows the log, and it is local: no key, and no witnesses are contacted. A ref already at its latest logged state is skipped.

The new entries sit past the stored checkpoint until `checkpoint` has a quorum cosign the log's new head, and until then nothing verifies against them.

### `git-ratchet checkpoint`

```
git-ratchet checkpoint --key <path> --policy <path> [--origin <name>] [flags]
```

Signs the log's head, submits it to the witnesses in the policy file, collects cosignatures, evaluates quorum, and stores the result. There is no `--ref`: a checkpoint covers whatever the log holds.

`--github-token` supplies the token a `github-issue://` witness needs. A policy naming one with no token is an error rather than a skipped witness, since skipping would lower the quorum without saying so.

### `git-ratchet verify`

```
git-ratchet verify --policy <path> --ref <refpath> [--ref <refpath>...] [flags]
```

Verifies the log's checkpoint against the policy, then walks the logged entries for each ref, checking that branch history only ever moved forward, that no tag was ever logged at a second object, and that the ref is not ahead of what the log covers. The `--ref` flag can be repeated to verify multiple refs.

Only the checkpointed prefix of the log is read. Entries appended past the last cosigned checkpoint are not yet witnessed, so nothing verifies against them.

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

This section walks through the full end-to-end setup: generating an origin signing key, setting up a witness, writing a policy, and then logging, checkpointing and verifying a repository.

### 1. Generate an origin signing key

```bash
bazel run //tools/genkey -- --role=origin --algo=mldsa44 --name=example.com/myrepo > origin.key
```

The private key goes to stdout in the [signed-note](https://c2sp.org/signed-note@v1.0.0) encoding; the **origin vkey** is printed to stderr. Keep the vkey — it goes in the policy.

The `--name` is load-bearing: it becomes the log's origin, which is what a witness keys its state by. `--algo` is `ed25519` or `mldsa44`.

Alternatively, [deploy/origin/README.md](deploy/origin/README.md) provisions a GCP Cloud KMS key that never leaves the HSM, used with `--kms-key` and `--origin` in place of `--key`. Ed25519 (`EC_SIGN_ED25519`) and ML-DSA-44 (`PQ_SIGN_ML_DSA_44`) keys are both supported; other ML-DSA parameter sets are not, because signed-note assigns an algorithm identifier to ML-DSA-44 alone.

### 2. Set up a witness

Any [tlog-witness](https://c2sp.org/tlog-witness) implementation will do. The simplest to run yourself is a [GitHub Issue witness](docs/github-issue-witness.md), which needs no server: follow that guide to create the repository, generate its key and register your origin. At the end you will have a **witness vkey** and a `github-issue://<owner>/<repo>` URL.

### 3. Write a policy file

Create a `policy.txt` (not committed) naming the origin key, the witness, and the quorum:

```
log <origin-vkey>

witness w1 <witness-vkey> <witness-url>

quorum w1
```

Note the field order: [tlog-policy](https://c2sp.org/tlog-policy) puts the **vkey before the URL**. For example:

```
log example.com/myrepo+a1b2c3d4+AAAA...

witness w1 github.com/me/git-witness+e5f6a7b8+BBBB... github-issue://me/git-witness

quorum w1
```

### 4. Log, checkpoint and verify

You can either build the binary once and run it directly, or use `bazel run` to build-and-run in a single step.

**Log** a ref, after a push:

```bash
bazel run //:git-ratchet -- log --ref refs/heads/main
```

**Checkpoint** the log, getting its head cosigned:

```bash
bazel run //:git-ratchet -- checkpoint \
  --key origin.key \
  --policy $PWD/policy.txt \
  --github-token "$TOKEN" \
  --witness-timeout 5m
```

`--github-token` and the longer timeout are for a GitHub Issue witness, whose reply takes as long as its workflow needs to queue and run. An HTTP witness needs neither.

To inspect the log and its checkpoint:

```bash
git log --oneline refs/ratchet/log
```

**Verify** that a ref is covered by the witnessed log:

```bash
bazel run //:git-ratchet -- verify --policy $PWD/policy.txt --ref refs/heads/main
```

Alternatively, build the binary once and invoke it directly:

```bash
bazel build //:git-ratchet
./bazel-bin/git-ratchet_/git-ratchet log --ref refs/heads/main
./bazel-bin/git-ratchet_/git-ratchet checkpoint --key origin.key --policy $PWD/policy.txt
./bazel-bin/git-ratchet_/git-ratchet verify --policy $PWD/policy.txt --ref refs/heads/main
```

## Self-witnessing

git-ratchet uses itself to protect its own `main` branch and release tags. Every push to `main` and every `v*` tag triggers the [checkpoint workflow](.github/workflows/checkpoint.yml), which submits the checkpoint to a witness at [`BenBirt/git-witness`](https://github.com/BenBirt/git-witness).

The witness policy is in [`ratchet-checkpoint.policy`](ratchet-checkpoint.policy). Anyone can verify the integrity of this repository:

```bash
git fetch origin 'refs/ratchet/log:refs/ratchet/log'
git-ratchet verify --policy ratchet-checkpoint.policy --ref refs/heads/main
```

## Talk

An overview deck is published at
**[project-oak.github.io/git-ratchet](https://project-oak.github.io/git-ratchet/)**,
built from [`presentation/`](presentation/index.html) on every change to it.

Press `N` for speaker notes and `P` for a presenter window; the arrow keys and
the on-screen buttons both move between slides.

## Disclaimer

This is not an officially supported Google product. This project is not
eligible for the [Google Open Source Software Vulnerability Rewards
Program](https://bughunters.google.com/open-source-security).
