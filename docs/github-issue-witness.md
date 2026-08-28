# GitHub Issue Witness

A `github-issue` witness is a Git repository on GitHub that acts as a witness
using GitHub Issues and GitHub Actions. Instead of deploying an HTTP server, the
origin creates an issue containing the checkpoint request and the witness repo's
GitHub Actions workflow verifies and cosigns it, posting the cosignature as a
comment.

The witness state is stored in the repo itself as committed files, and the
full audit trail is preserved in the repo's commit history.

A `github-issue` witness serves [`tlog` mode](tlog-variant.md) only.
`git-checkpoint` mode reaches its witnesses over HTTP, because its witnesses
verify Git commit ancestry and so must run git-ratchet's own witness; see
[docs/witness-protocol.md](witness-protocol.md).

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

The exchange is the [tlog-witness][] `add-checkpoint` exchange, unchanged. Only
the wire differs: an issue carries the request and a comment carries the
response, in place of a POST and its reply.

[tlog-witness]: https://c2sp.org/tlog-witness

### Framing

Each message is one HTTP message, serialised as `message/http`
([RFC 9112][]), in a fenced block tagged `http`:

    ```http
    POST /add-checkpoint HTTP/1.1
    Host: witness.invalid
    Content-Length: 186

    old 0

    example.com/repo
    1
    q1s6ZW51k4Bgvzp0KgnkY5bhwXCbLpXV4uOxNZ0DvGw=

    — example.com/repo AAAA...
    ```

Both sides produce and consume these with the standard library, so nothing
about the protocol is reimplemented for this transport.

Three rules the carrier imposes:

- **Line endings are LF, not the CRLF [RFC 9112][] specifies.** GitHub
  normalises CRLF to LF in issue and comment text, so a message sent with CRLF
  does not come back as it was sent. Sending LF makes the two identical, and
  Go's parsers accept it. Nothing may depend on the serialisation being stable
  in any case: it is a wire, not something signed.
- **`Content-Length` is required**, and chunked encoding MUST NOT be used.
  Without it a body runs to the end of the message, and anything the carrier
  appends — a trailing newline from a comment box — is read as part of it.
- **`Host` is `witness.invalid`.** RFC 9112 requires a Host on every HTTP/1.1
  request, but one request may be carried to several witnesses and the carrier
  addresses them out of band, so there is no host to name. A reserved name
  ([RFC 2606][]) says that rather than implying an address.

The owner and repository in a `github-issue://` URL say which issue thread to
post to, not which resource is being addressed, so they do not appear in the
message. A witness routes `/add-checkpoint` exactly as it would over HTTP.

[RFC 9112]: https://www.rfc-editor.org/rfc/rfc9112.html
[RFC 2606]: https://www.rfc-editor.org/rfc/rfc2606.html

### One issue, one exchange

An issue carries exactly one request and receives exactly one response. There
is no reuse: a second request — a resubmission after a `409`, say — opens a new
issue.

Carrying two exchanges on one issue would be HTTP/1.1 pipelining, where a
response is paired to a request by ordering. The witness is a workflow run per
message, and two runs can finish out of order, so the pairing would not hold.

### Witness side (`actions/cosign`)

When an issue arrives, the cosign action:

1. Reads the `http` block from the issue body.
2. Takes the origin from the first line of the checkpoint, and checks it is
   registered (has a `checkpoints/<origin>/vkeys.txt`).
3. Runs the `cosign` binary, which parses the request, hands it to
   [transparency-dev/witness][witness-impl]'s own `add-checkpoint` handler, and
   serialises what that handler returns. A `github-issue` witness therefore
   answers exactly as an HTTP one would, down to the status code and the
   `Content-Type` on a size conflict.
4. Commits the updated state at `checkpoints/<origin>/checkpoint`. There is one
   log per origin, so there is one state file per origin.
5. Posts the response as a comment, whatever its status: a refusal is an
   answer, and the origin needs to read it.
6. Closes the issue.

On failure — the origin is not registered, or the request will not parse — it
posts an error comment with a link to the workflow run and closes the issue as
not planned.

[witness-impl]: https://github.com/transparency-dev/witness

## Setting up a new witness repo

### 1. Create a GitHub repo

Create a new repository (e.g. `my-org/git-witness`). It can be public or
private.

### 2. Generate a witness key pair

Generate a key pair using the `genkey` tool:

```bash
bazel run //tools/genkey -- --role=witness --name=<name> [--algo=<algo>] > witness-key
```

Where `<algo>` is one of `ed25519` (default) or `mldsa44`. `mldsa44` keys serve
`tlog` mode only; see [docs/tlog-variant.md](tlog-variant.md).
This outputs the key content (the vkey followed by the base64-encoded seed) to stdout,
and prints the verifier key (vkey) to stderr.


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

As the witness cosigns checkpoints, its state is committed alongside the keys:

```
checkpoints/<origin>/checkpoint
```

For example: `checkpoints/github.com/example/repo/checkpoint`. There is one log
per origin, so there is one state file per origin; the ratchet is over the
log's tree size, not over any one ref.

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

The issue title is `checkpoint: <origin>`. The `if` guard prevents the workflow
from triggering on non-checkpoint issues, and the `concurrency` group keys on
the title, which serialises cosign jobs per origin and stops two runs racing on
the same state file when checkpoints arrive in quick succession.

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
