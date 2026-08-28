# git-ratchet checkpoint action

A composite GitHub Action that runs the full origin-side checkpoint lifecycle:
creates a checkpoint request, submits it to all witnesses, collects
cosignatures, evaluates quorum, and stores the result.

## How it works

1. Checks out the repository with full history (`fetch-depth: 0`).
2. Installs git-ratchet via the [`setup`](../setup) action.
3. Fetches existing checkpoint refs from origin.
4. Runs `git-ratchet checkpoint`, which signs the checkpoint, submits it to
   every witness declared in the policy file, verifies quorum, and stores the
   result.
5. Pushes the checkpoint ref (`refs/checkpoints/…`) to origin.

## Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ref` | Yes | — | Full ref path to checkpoint (e.g. `refs/heads/main`). |
| `origin-key` | Yes | — | Origin Ed25519 private key file contents (vkey + seed). |
| `policy` | Yes | — | Path to the witness policy file (relative to repo root). |
| `github-token` | No | `github.token` | GitHub token with permission to create issues on witness repos. |
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
