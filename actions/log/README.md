# git-ratchet log action

A composite GitHub Action that records a ref's current object in the
repository's transparency log and pushes the entry.

This is the only thing that grows the log, and it is local: no key, and no
witnesses are contacted. Entries sit past the stored checkpoint until
[`checkpoint`](../checkpoint) has a quorum cosign the log's new head, and
until then nothing verifies against them.

## How it works

1. Checks out the repository with full history (`fetch-depth: 0`).
2. Installs git-ratchet via the [`setup`](../setup) action.
3. Fetches `refs/ratchet/log`, which does not exist on a first run.
4. Records the ref (`git-ratchet log --ref`).
5. Pushes the entry.

The push is not forced. Each log commit is parented on the one before, so an
ordinary push rejects a rewritten log before any git-ratchet code runs — a
check worth keeping rather than overriding.

## Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ref` | Yes | — | Full ref path to record (e.g. `refs/heads/main`). |
| `version` | No | `latest` | git-ratchet version to install. |

## Permissions

```yaml
permissions:
  contents: write   # push refs/ratchet/log
```

## Usage

Logging on every push and checkpointing on a schedule keeps the ref record
prompt while asking witnesses for far fewer signatures:

```yaml
name: Log
on:
  push:
    branches: [main]
    tags: ['v*']

concurrency:
  group: git-ratchet-log
  cancel-in-progress: false

jobs:
  log:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: project-oak/git-ratchet/actions/log@main
        with:
          ref: ${{ github.ref }}
```

That workflow needs a companion: entries sit past the stored checkpoint until
something cosigns the log's new head. Run [`checkpoint`](../checkpoint) on a
schedule against the same repository, or run both on one event — its README
carries that workflow in full.

Whichever arrangement, give every workflow that writes `refs/ratchet/log` the
same repository-wide `concurrency` group. Two runs starting from the same log
head will race, and the loser's push is rejected.
