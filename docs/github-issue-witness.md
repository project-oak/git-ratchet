# GitHub Issue Witness

A `github-issue` witness is a Git repository on GitHub that acts as a witness
using GitHub Issues and GitHub Actions. Instead of deploying an HTTP server, the
origin creates an issue containing the checkpoint request and the witness repo's
GitHub Actions workflow verifies and cosigns it, posting the cosignature as a
comment.

The witness state is stored in the repo itself as committed files, and the
full audit trail is preserved in the repo's commit history.

## Policy format

In a policy file, declare a GitHub Issue witness using the `github-issue://`
URI scheme:

```
witness <name> github-issue://<owner>/<repo> <vkey>
```

Example:

```
witness mywitness github-issue://example-org/my-witness example-witness+abcd1234+AAAA...
```

## Protocol

### Origin side (`actions/checkpoint`)

The origin's checkpoint action performs the following steps:

1. Creates a GitHub Issue on the witness repo with the `add-checkpoint` request
   body in a fenced code block:

       ```add-checkpoint
       <request body>
       ```

   The issue title is `checkpoint: <origin> <ref>`.

2. Polls the issue every 5 seconds until it is closed (configurable timeout,
   default 300s).

3. When closed, reads the issue comments looking for one starting with `— `
   (the cosignature line prefix).

4. Saves the cosignature for assembly.

The origin requires a GitHub token (`github-token` input) with permission to
create issues on the witness repo.

### Witness side (`actions/cosign`)

When an issue arrives, the cosign action:

1. Parses the `add-checkpoint` block from the issue body.
2. Checks that the origin is registered (has a `checkpoints/<origin>/vkeys.txt`).
3. Runs the `cosign` binary with `--stored-checkpoint` pointing to the last
   cosigned checkpoint file, if one exists.
4. Commits the updated checkpoint to the repo.
5. Posts the cosignature as a comment on the issue.
6. Closes the issue as completed.

On failure, it posts an error comment with a link to the workflow run and closes
the issue as not planned.

## Setting up a new witness repo

### 1. Create a GitHub repo

Create a new repository (e.g. `my-org/git-witness`). It can be public or
private.

### 2. Generate a witness key pair

Generate a key pair using the `genwitnesskey` tool:

```bash
bazel run //tools/genwitnesskey -- --output-dir=<output-dir> --name=<name>
```

This writes a `witness-key` file to `<output-dir>` and prints the verifier key
(vkey) to stderr. The key file format is two lines: the vkey, followed by the
base64-encoded seed.

### 3. Store the key as a secret

Add the full contents of the key file as a GitHub Actions secret (e.g.
`WITNESS_KEY`).

### 4. Create the directory structure

For each origin you want to witness, create:

```
checkpoints/<origin>/vkeys.txt
```

where `<origin>` is the origin identifier (e.g. `github.com/example/repo`).
The `vkeys.txt` file lists trusted origin verifier keys, one per line. Lines
starting with `#` are comments.

As the witness cosigns checkpoints, checkpoint files are committed alongside
the keys:

```
checkpoints/<origin>/<ref>
```

For example: `checkpoints/github.com/example/repo/refs/heads/main`.

### 5. Create a workflow

Add a workflow file (e.g. `.github/workflows/cosign.yml`):

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

The `if` guard prevents the workflow from triggering on non-checkpoint issues.
The `concurrency` group serialises cosign jobs per origin and ref (derived from
the issue title `checkpoint: <origin> <ref>`), preventing race conditions when
multiple checkpoints arrive in quick succession.

The workflow needs `contents: write` to commit updated checkpoint files and
`issues: write` to post comments and close issues.

#### Handling infrastructure failures

The `actions/cosign` action closes the issue on failure, but only if a step
actually runs. If the job itself fails during setup (e.g. the action ref cannot
be resolved), the issue is left open. To handle this, add a separate cleanup
job:

```yaml
  cleanup:
    needs: cosign
    if: >-
      always() &&
      startsWith(github.event.issue.title, 'checkpoint:') &&
      needs.cosign.result == 'failure'
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - name: Close issue on failure
        env:
          ISSUE: ${{ github.event.issue.number }}
          GH_TOKEN: ${{ github.token }}
          GH_REPO: ${{ github.repository }}
        run: |
          gh issue comment "$ISSUE" \
            --body "❌ Rejected. See [workflow run](${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }})."
          gh issue close "$ISSUE" --reason "not planned"
```

### 6. Configure the origin

On the origin side, add the witness to your policy file:

```
witness mywitness github-issue://my-org/git-witness <witness-vkey>
```

## Advantages over HTTP witnesses

- **No server to deploy or maintain.** The witness runs entirely as a GitHub
  Actions workflow.
- **Full audit trail.** Every cosigned checkpoint is committed to the witness
  repo, preserving a complete history of witnessed state transitions.
- **State persisted in git.** Checkpoint files are committed to the witness
  repo, providing a durable and versioned record.
- **Works entirely within GitHub Actions.** No additional infrastructure
  required beyond a GitHub repo and a secret.
