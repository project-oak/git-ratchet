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
3. Reads the `http` fenced code block from the issue body: one `message/http`
   add-checkpoint request.
4. Verifies the origin is registered (`origins/<origin>` must exist).
5. Runs the cosign binary, which answers the request with the standard
   `add-checkpoint` handler.
6. Commits the updated state at `checkpoints/<origin>`, if the request was
   accepted and the state changed.
7. Posts the response as a comment, whatever its status.
8. Closes the issue (`completed` once answered, `not planned` on failure).

## Required Permissions

- `contents: write` — to commit checkpoint state
- `issues: write` — to comment on and close issues

## Witness Repository Layout

```
origins/
  <origin>                 # Trusted origin verifier keys (one per line)
checkpoints/
  <origin>                 # Last cosigned checkpoint for this origin's log
```

`<origin>` is the origin identifier, so a witness for
`github.com/example/repo` has `origins/github.com/example/repo` and
`checkpoints/github.com/example/repo`.

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
