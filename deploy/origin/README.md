# Deploying the git-ratchet origin KMS key

This directory provisions a GCP Cloud KMS Ed25519 signing key for the
git-ratchet log origin. The `git-ratchet checkpoint` command uses this key
to sign checkpoints via the `--kms-key` flag.

## Prerequisites

- [Bazel](https://bazel.build/) 9+ (or Bazelisk)
- `gcloud` CLI, authenticated (`gcloud auth login`)
- A GCP project with billing enabled
- Cloud KMS API enabled (`cloudkms.googleapis.com`)

## 1. Configure the GCP project

Set your GCP project ID in `deploy/origin/BUILD.bazel`:

```python
tf_deploy(
    name = "origin",
    deps = [":origin_lib"],
    vars = {
        "project": "my-gcp-project",  # ← your project
        "region": "us-central1",
    },
)
```

## 2. Deploy

```bash
bazel run //deploy/origin:origin.apply
```

This creates a KMS key ring (`git-ratchet-origin`) and an Ed25519 signing
key (`origin-signing-key`).

## 3. Extract the origin vkey

The origin's verifier key (vkey) must be added to the witness's trusted
origins file so the witness accepts checkpoints signed by this key.

```bash
# Get the KMS key version resource name.
KMS_KEY=$(gcloud kms keys versions list \
  --project=PROJECT \
  --location=us-central1 \
  --keyring=git-ratchet-origin \
  --key=origin-signing-key \
  --filter="state=ENABLED" \
  --format="value(name)" \
  --limit=1)

# Print the vkey.
bazel run //tools/kmsvkey -- \
  --kms-key="$KMS_KEY" \
  --name=git-ratchet-origin \
  --role=origin
```
