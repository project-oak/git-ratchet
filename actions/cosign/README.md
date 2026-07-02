# `git-ratchet cosign` Action

A composite GitHub Action that cosigns checkpoint requests in a **witness
repository**. It processes checkpoint requests submitted as GitHub Issues and
commits cosigned checkpoints back to the repository.

## Trigger

This action should be triggered by `issues: opened` events.

## Inputs

| Name | Required | Description |
|------|----------|-------------|
| `witness-key` | Yes | Witness Ed25519 private key file contents (vkey + seed) |

## What It Does

1. Checks out the witness repository.
2. Installs the standalone `cosign` binary.
3. Parses the issue body for an `add-checkpoint` fenced code block.
4. Verifies the origin is registered (`checkpoints/<origin>/vkeys.txt` must
   exist).
5. Runs the cosign binary with the stored checkpoint (if any) for state
   tracking.
6. Commits the cosigned checkpoint to the repo under
   `checkpoints/<origin>/<ref>`.
7. Posts the cosignature as a comment on the issue.
8. Closes the issue (`completed` on success, `not planned` on failure).

## Required Permissions

- `contents: write` — to commit checkpoint state
- `issues: write` — to comment on and close issues

## Witness Repository Layout

```
checkpoints/
  <origin>/
    vkeys.txt              # Trusted origin verifier keys (one per line)
    refs/heads/main        # Last cosigned checkpoint for this ref
    refs/tags/v1.0.0       # Last cosigned checkpoint for this tag
```

## Example Workflow

Create `.github/workflows/cosign.yml` in the witness repository:

```yaml
name: Cosign
on:
  issues:
    types: [opened]
jobs:
  cosign:
    if: startsWith(github.event.issue.title, 'checkpoint:')
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
    concurrency:
      group: cosign-${{ github.event.issue.title }}
      cancel-in-progress: false
    steps:
      - uses: project-oak/git-ratchet/actions/cosign@main
        with:
          witness-key: ${{ secrets.WITNESS_KEY }}
```

## Further Reading

See [docs/github-issue-witness.md](../../docs/github-issue-witness.md) for the
full setup guide.
