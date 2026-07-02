# `git-ratchet setup` Action

A composite GitHub Action that installs `git-ratchet` or `cosign` on a runner.

## Inputs

| Name           | Required | Default        | Description                                      |
|----------------|----------|----------------|--------------------------------------------------|
| `tool`         | Yes      |                | Which tool to install: `git-ratchet` or `cosign` |
| `version`      | No       | `latest`       | Release version to install (e.g. `v0.1.0`)       |
| `github-token` | No       | `github.token` | GitHub token for API calls (avoids rate limits)   |

## How it works

1. Detects the runner's OS and architecture.
2. Downloads the specified tool from the
   [git-ratchet GitHub Releases](https://github.com/project-oak/git-ratchet/releases).
3. Extracts the tarball and adds the binary to `PATH`.

**Supported platforms:** `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`

## Usage

```yaml
steps:
  - uses: project-oak/git-ratchet/actions/setup@main
    with:
      tool: git-ratchet
      version: v0.1.0
```
