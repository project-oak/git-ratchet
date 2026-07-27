# GitLab Issue Witness

A `gitlab-issue` witness is a Git repository on GitLab that acts as a witness
using GitLab Issues and GitLab CI/CD. Instead of deploying an HTTP server, the
origin creates an issue containing the checkpoint request and the witness repo's
CI pipeline verifies and cosigns it, posting the cosignature as a comment.

The witness state is stored in the repo itself as committed files, and the
full audit trail is preserved in the repo's commit history.

## Policy format

In a policy file, declare a GitLab Issue witness using the `gitlab-issue://`
URI scheme:

```
witness <name> gitlab-issue://<host>/<project-path> <vkey>
```

The host is always explicit (GitLab supports self-hosted instances). The project
path may contain nested groups.

Example:

```
witness mywitness gitlab-issue://gitlab.example.com/group/subgroup/my-witness example-witness+abcd1234+AAAA...
```

For gitlab.com-hosted projects:

```
witness mywitness gitlab-issue://gitlab.com/my-org/my-witness example-witness+abcd1234+AAAA...
```

## Protocol

The protocol is identical to the [GitHub Issue witness](github-issue-witness.md)
protocol, adapted for GitLab APIs.

### Origin side (`actions/checkpoint`)

The origin's checkpoint action performs the following steps:

1. Creates a GitLab Issue on the witness project with the `add-checkpoint`
   request body in a fenced code block:

       ```add-checkpoint
       <request body>
       ```

   The issue title is `checkpoint: <origin> <ref>`.

2. Polls the issue every 5 seconds until it is closed (configurable timeout,
   default 300s).

3. When closed, reads the issue notes (comments) looking for one starting with
   `— ` (the cosignature line prefix).

4. Saves the cosignature for assembly.

The origin requires a GitLab token (`gitlab-token` input) with permission to
create and read issues on the witness project (`api` scope, Reporter role). A
single token covers all GitLab Issue witnesses on the same instance.

### Witness side (`gitlab/cosign.gitlab-ci.yml`)

When an issue arrives, the GitLab CI cosign job:

1. Parses the `add-checkpoint` block from the issue description.
2. Checks that the origin is registered (has a `checkpoints/<origin>/vkeys.txt`).
3. Runs the `cosign` binary with `--stored-checkpoint` pointing to the last
   cosigned checkpoint file, if one exists.
4. Commits the updated checkpoint to the repo.
5. Posts the cosignature as a comment on the issue.
6. Closes the issue.

On failure, it posts an error comment with a link to the pipeline and closes
the issue.

## Triggering

This is the main structural difference from the GitHub flavor. GitLab CI cannot
run pipelines directly from issue events. Instead, triggering is self-wired via
a project webhook:

1. A **project webhook** on **Issues events** points at the project's own
   pipeline trigger endpoint:
   ```
   https://<host>/api/v4/projects/<id>/ref/<default-branch>/trigger/pipeline?token=<trigger-token>
   ```

2. When an issue is created (or updated), the webhook fires and triggers a new
   pipeline.

3. The pipeline's cosign job filters on `$CI_PIPELINE_SOURCE == "trigger"` and
   scans all open `checkpoint:`-titled issues.

**Consequences:**

- The **origin** needs only one token (to create and read issues — `api` scope,
  Reporter role). It does not need a trigger token.
- The **webhook cannot pass the issue IID**, so the cosign job scans all open
  `checkpoint:`-titled issues in each run.
- Webhooks also fire on issue update and close events, yielding harmless no-op
  pipelines (no open checkpoint issues to process).

## Setting up a new witness project

### 1. Create a GitLab project

Create a new project (e.g. `my-group/git-witness`). It can be public or
private.

### 2. Generate a witness key pair

Generate a key pair using the `genwitnesskey` script:

```bash
bazel run //tools:genwitnesskey -- <output-dir> <name>
```

This writes a `witness-key` file to `<output-dir>` and prints the verifier key
(vkey) to stdout. The key file format is two lines: the vkey, followed by the
base64-encoded seed.

### 3. Store the key and token as CI/CD variables

Add two CI/CD variables in **Settings → CI/CD → Variables**:

| Variable | Type | Properties | Value |
|----------|------|------------|-------|
| `WITNESS_KEY` | File | Protected | Full contents of the key file (vkey + base64 seed) |
| `WITNESS_API_TOKEN` | Variable | Masked, Protected | Project access token (`api` scope, Maintainer role — needed to push to the protected default branch) |

### 4. Create a pipeline trigger token

In **Settings → CI/CD → Pipeline trigger tokens**, create a new trigger token.
Save the token value — you'll need it for the webhook.

### 5. Set up the webhook

In **Settings → Webhooks**, add a new webhook:

- **URL**: `https://<host>/api/v4/projects/<project-id>/ref/<default-branch>/trigger/pipeline?token=<trigger-token>`
- **Trigger**: Issues events
- **SSL verification**: Enable (unless using a self-signed certificate)

> **Self-hosted caveat**: If the GitLab instance and the witness project are on
> the same host, you must enable **"Allow requests to the local network from
> webhooks and integrations"** in **Admin Area → Settings → Network → Outbound
> requests**. Without this, the webhook will be blocked by GitLab's default
> loopback prevention.

### 6. Create the directory structure

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

### 7. Add the CI configuration

Add a `.gitlab-ci.yml` that includes the cosign template:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/project-oak/git-ratchet/main/gitlab/cosign.gitlab-ci.yml'
```

Or copy [`gitlab/cosign.gitlab-ci.yml`](../gitlab/cosign.gitlab-ci.yml) into
your project and include it locally:

```yaml
include:
  - local: 'cosign.gitlab-ci.yml'
```

### 8. Configure the origin

On the origin side, add the witness to your policy file:

```
witness mywitness gitlab-issue://gitlab.example.com/my-group/git-witness <witness-vkey>
```

In the origin's GitHub Actions workflow, pass a GitLab token:

```yaml
- uses: project-oak/git-ratchet/actions/checkpoint@main
  with:
    ref: ${{ github.ref }}
    origin-key: ${{ secrets.ORIGIN_KEY }}
    policy: ratchet-checkpoint.policy
    gitlab-token: ${{ secrets.GITLAB_WITNESS_TOKEN }}
```

The GitLab token needs `api` scope and at least Reporter role on the witness
project. A single token can be used for all GitLab Issue witnesses on the same
instance.

## Advantages over HTTP witnesses

- **No server to deploy or maintain.** The witness runs entirely as a GitLab
  CI/CD pipeline.
- **Full audit trail.** Every cosigned checkpoint is committed to the witness
  repo, preserving a complete history of witnessed state transitions.
- **State persisted in git.** Checkpoint files are committed to the witness
  repo, providing a durable and versioned record.
- **Works entirely within GitLab CI/CD.** No additional infrastructure
  required beyond a GitLab project and CI/CD variables.
- **Self-hosted support.** Works with any GitLab instance, not just gitlab.com.
