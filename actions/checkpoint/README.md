# git-ratchet checkpoint action

A composite GitHub Action that runs the full origin-side checkpoint lifecycle:
creates a checkpoint request, submits it to all witnesses, collects
cosignatures, evaluates quorum, and stores the result.

Supports HTTP witnesses, GitHub Issue witnesses (`github-issue://`), and
GitLab Issue witnesses (`gitlab-issue://`).

## How it works

1. Checks out the repository with full history (`fetch-depth: 0`).
2. Installs git-ratchet via the [`setup`](../setup) action.
3. Fetches existing checkpoint refs from origin.
4. Creates a checkpoint request (signs the checkpoint and builds an ancestry
   proof).
5. Submits to every witness declared in the policy file:
   - **HTTP witnesses** — direct `POST` to the witness URL.
   - **`github-issue://` witnesses** — creates a GitHub Issue on the witness
     repo, then polls for a cosignature comment until the issue is closed or
     the timeout expires.
   - **`gitlab-issue://` witnesses** — creates a GitLab Issue on the witness
     project via the GitLab API, then polls for a cosignature note until the
     issue is closed or the timeout expires.
6. Assembles cosignatures, verifies quorum, and stores the checkpoint.
7. Pushes the checkpoint ref (`refs/checkpoints/…`) to origin.

## Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ref` | Yes | — | Full ref path to checkpoint (e.g. `refs/heads/main`). |
| `origin-key` | Yes | — | Origin Ed25519 private key file contents (vkey + seed). |
| `policy` | Yes | — | Path to the witness policy file (relative to repo root). |
| `github-token` | No | `github.token` | GitHub token with permission to create issues on witness repos. |
| `gitlab-token` | No | `''` | GitLab token with `api` scope and Reporter role on witness projects. One token covers all `gitlab-issue://` witnesses on the same instance. |
| `version` | No | `latest` | git-ratchet version to install. |
| `timeout` | No | `300` | Timeout in seconds for GitHub/GitLab Issue witness polling. |

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

For `github-issue://` witnesses, pass a token that can create issues on the
witness repo:

```yaml
          github-token: ${{ secrets.WITNESS_GITHUB_TOKEN }}
```

For `gitlab-issue://` witnesses, pass a GitLab token with `api` scope:

```yaml
          gitlab-token: ${{ secrets.WITNESS_GITLAB_TOKEN }}
```

A single `gitlab-token` covers all GitLab Issue witnesses on the same instance.
See [docs/gitlab-issue-witness.md](../../docs/gitlab-issue-witness.md) for
setup instructions.
