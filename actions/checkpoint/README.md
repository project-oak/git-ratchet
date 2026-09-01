# git-ratchet checkpoint action

A composite GitHub Action that checkpoints the repository's transparency log:
submits the log's head to the policy's witnesses, collects cosignatures,
evaluates quorum, stores the result and pushes it.

Refs are recorded in the log by the [`log`](../log) action, which is a separate
step. A checkpoint covers whatever the log holds when it runs.

## How it works

1. Checks out the repository with full history (`fetch-depth: 0`).
2. Installs git-ratchet via the [`setup`](../setup) action.
3. Fetches `refs/ratchet/log`, which does not exist until something has been
   recorded in it.
4. Checkpoints the log (`git-ratchet checkpoint`), which collects
   cosignatures and stores the result.
5. Pushes the checkpoint.

The push is not forced. Each log commit is parented on the one before, so an
ordinary push rejects a rewritten log before any git-ratchet code runs — a
check worth keeping rather than overriding.

Keeping this separate from [`log`](../log) means a witness that is down, slow,
or refusing cannot cost the repository a log entry: the entry is already
pushed, and the next checkpoint covers it.

## Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `origin-key` | Yes | — | Origin private key file contents, as written by `genkey`. |
| `policy` | Yes | — | Path to the witness policy file (relative to repo root). |
| `github-token` | No | `github.token` | Token that can open issues on witness repositories, for `github-issue://` witnesses. |
| `version` | No | `latest` | git-ratchet version to install. |
| `timeout` | No | `300` | Seconds to wait for each witness to cosign. |

## Permissions

The workflow must grant:

```yaml
permissions:
  contents: write   # push refs/ratchet/log
```

## Usage

A checkpoint covers whatever the log holds, so something has to put a ref in
the log first. On its own this Action would checkpoint a log with no new
entries.

```yaml
name: Checkpoint
on:
  push:
    branches: [main]
    tags: ['v*']

# One log, one writer. Both jobs write refs/ratchet/log, so a push to main and
# a v* tag arriving together would race and the loser's push would be
# rejected. The group is deliberately not keyed on the ref: there is one log,
# not one per ref.
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

  checkpoint:
    needs: log
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: project-oak/git-ratchet/actions/checkpoint@main
        with:
          origin-key: ${{ secrets.ORIGIN_KEY }}
          policy: ratchet-checkpoint.policy
```

Reaching a `github-issue://` witness needs a token that can create issues on
the witness repository:

```yaml
          github-token: ${{ secrets.WITNESS_GITHUB_TOKEN }}
```

The two need not share a trigger. [`log`](../log) can run on every push while
this runs on a schedule, which keeps the ref record prompt while asking
witnesses for far fewer signatures.
