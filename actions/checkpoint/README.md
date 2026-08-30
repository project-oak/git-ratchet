# git-ratchet checkpoint action

A composite GitHub Action that runs the full origin-side checkpoint lifecycle:
records the ref, submits it to the policy's witnesses, collects cosignatures,
evaluates quorum, stores the result and pushes it.

## How it works

1. Checks out the repository with full history (`fetch-depth: 0`).
2. Installs git-ratchet via the [`setup`](../setup) action.
3. Fetches the ref the mode keeps its state in, which does not exist on a
   first run.
4. Runs the mode's commands.
5. Pushes that ref back to origin.

The two modes differ in every one of those steps but the second:

| | `git-checkpoint` | `tlog` |
|---|---|---|
| Fetches | `refs/checkpoints/*` | `refs/ratchet/log` |
| Runs | `checkpoint --ref` | `log --ref`, then `checkpoint` |
| Pushes | `refs/checkpoints/…`, forced | `refs/ratchet/log`, fast-forward |

The `tlog` push is deliberately not forced. Each log commit is parented on the
one before, so an ordinary push rejects a rewritten log before any git-ratchet
code runs — a check worth keeping rather than overriding. A `git-checkpoint`
ref holds one note rather than a chain, so it has nothing to fast-forward from.

## Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ref` | Yes | — | Full ref path to checkpoint (e.g. `refs/heads/main`). |
| `origin-key` | Yes | — | Origin Ed25519 private key file contents (vkey + seed). |
| `policy` | Yes | — | Path to the witness policy file (relative to repo root). |
| `mode` | No | `git-checkpoint` | Checkpoint format: `git-checkpoint` or `tlog`. |
| `github-token` | No | `github.token` | Token that can open issues on witness repositories, for `github-issue://` witnesses. `tlog` mode only. |
| `version` | No | `latest` | git-ratchet version to install. |
| `timeout` | No | `300` | Seconds to wait for each witness to cosign. |

## Permissions

The workflow must grant:

```yaml
permissions:
  contents: write   # push checkpoint refs
```

## Usage

```yaml
on:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  checkpoint:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: project-oak/git-ratchet/actions/checkpoint@main
        with:
          ref: ${{ github.ref }}
          origin-key: ${{ secrets.ORIGIN_KEY }}
          policy: ratchet-checkpoint.policy
```

`github-issue://` witnesses serve [`tlog` mode](../../docs/tlog-variant.md).
Reaching one needs a token that can create issues on the witness repo:

```yaml
          github-token: ${{ secrets.WITNESS_GITHUB_TOKEN }}
```
