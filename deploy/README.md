# Deploying the git-ratchet witness

This directory contains everything needed to deploy the git-ratchet witness
to GCP Cloud Run via Bazel.

## Prerequisites

- [Bazel](https://bazel.build/) 9+ (or Bazelisk)
- `gcloud` CLI, authenticated (`gcloud auth login`)
- A GCP project with billing enabled
- The following APIs enabled on the project:
  - Cloud Run Admin (`run.googleapis.com`)
  - Artifact Registry (`artifactregistry.googleapis.com`)
  - Cloud Storage (`storage.googleapis.com`)

## 1. Generate witness key

```bash
bazel run //deploy/witness:genkeys -- $PWD/deploy/witness
```

This creates `deploy/witness/witness-key` (git-ignored), the witness's
Ed25519 cosigner private key.

Separately, populate `deploy/witness/origins` (also git-ignored) with the
vkeys of trusted log origins, one per line.

## 2. Configure the GCP project

Set your GCP project ID in two places:

1. **`deploy/witness/BUILD.bazel`** — replace `PROJECT` in the `vars` block:

   ```python
   tf_deploy(
       name = "witness",
       deps = [":witness_lib"],
       vars = {
           "project": "my-gcp-project",  # ← your project
           "region": "us-central1",
       },
   )
   ```

2. **`witness/BUILD.bazel`** — replace `PROJECT` in the `oci_push` repository:

   ```python
   oci_push(
       name = "witness_push",
       image = ":witness_image",
       repository = "us-central1-docker.pkg.dev/my-gcp-project/git-ratchet/witness",
       remote_tags = ["latest"],
   )
   ```

## 3. First deploy

On the first deploy, both the Artifact Registry (for the container image) and
the GCS bucket (for the witness key) must exist before Cloud Run can start.
Bootstrap in this order:

```bash
# 1. Create everything except Cloud Run (registry + bucket must exist first).
bazel run //deploy/witness:witness.apply -- \
  -exclude=google_cloud_run_v2_service.witness \
  -exclude=google_cloud_run_v2_service_iam_member.public

# 2. Push the container image (now that the registry exists).
gcloud auth configure-docker us-central1-docker.pkg.dev
bazel run //witness:witness_push

# 3. Upload the witness key and origins to GCS (the container reads these
#    at startup via the GCS FUSE volume mount — they must exist before
#    Cloud Run tries to start the service).
bazel run //deploy/witness:upload_keys -- \
  <PROJECT>-git-ratchet-witness \
  deploy/witness/witness-key \
  deploy/witness/origins

# 4. Full apply — creates Cloud Run (container can now start successfully).
bazel run //deploy/witness:witness.apply
```

Replace `<PROJECT>` with your GCP project ID.

> **Note:** Terraform state is stored locally (in `bazel-bin/`). For production,
> add a `backend "gcs" {}` block to `main.tf`.

On subsequent deploys (e.g. after code changes), just push and apply:

```bash
bazel run //witness:witness_push
bazel run //deploy/witness:witness.apply
```

## 4. Verify

After deployment, the witness URL is printed as a Terraform output. Test it:

```bash
WITNESS_URL=$(gcloud run services describe git-ratchet-witness \
  --region=us-central1 \
  --project=PROJECT \
  --format='value(status.url)')
curl -s "$WITNESS_URL/add-checkpoint"
```

A `method not allowed` response indicates that the witness is serving.
