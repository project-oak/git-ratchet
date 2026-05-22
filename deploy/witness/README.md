# Deploying the git-ratchet witness

This directory contains everything needed to deploy the git-ratchet witness
to GCP Cloud Run via Bazel. Witness signing uses GCP Cloud KMS (Ed25519).

## Prerequisites

- [Bazel](https://bazel.build/) 9+ (or Bazelisk)
- `gcloud` CLI, authenticated (`gcloud auth login`)
- A GCP project with billing enabled
- The following APIs enabled on the project:
  - Cloud Run Admin (`run.googleapis.com`)
  - Artifact Registry (`artifactregistry.googleapis.com`)
  - Cloud Storage (`storage.googleapis.com`)
  - Cloud KMS (`cloudkms.googleapis.com`)

## 1. Configure the GCP project

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

## 2. Prepare trusted origins

Populate `deploy/witness/origins` with the vkeys of trusted log origins,
one per line. These are the origin keys that the witness will accept
checkpoints from.

## 3. First deploy

On the first deploy, the Artifact Registry, GCS bucket, and KMS key must
exist before Cloud Run can start. Bootstrap in this order:

```bash
# 1. Create everything except Cloud Run (registry + bucket + KMS must exist first,
#    and Terraform will upload the origins file to GCS automatically).
bazel run //deploy/witness:witness.apply -- \
  -exclude=google_cloud_run_v2_service.witness \
  -exclude=google_cloud_run_v2_service_iam_member.public

# 2. Push the container image (now that the registry exists).
gcloud auth configure-docker us-central1-docker.pkg.dev
bazel run //witness:witness_push

# 3. Full apply — creates Cloud Run (container can now start successfully).
bazel run //deploy/witness:witness.apply
```

> **Note:** Terraform state is stored locally (in `bazel-bin/`). For production,
> add a `backend "gcs" {}` block to `main.tf`.

On subsequent deploys (e.g. after code changes), just push and apply:

```bash
bazel run //witness:witness_push
bazel run //deploy/witness:witness.apply
```

## 4. Extract the witness vkey

After deployment, extract the witness's verifier key (vkey) from the KMS
signing key. This vkey is what clients put in their policy files to verify
cosignatures from this witness.

```bash
# Get the KMS key version resource name.
KMS_KEY=$(gcloud kms keys versions list \
  --project=PROJECT \
  --location=us-central1 \
  --keyring=git-ratchet-witness \
  --key=witness-signing-key \
  --filter="state=ENABLED" \
  --format="value(name)" \
  --limit=1)

# Print the vkey.
bazel run //tools/kmsvkey -- \
  --kms-key="$KMS_KEY" \
  --name=git-ratchet-witness
```

## 5. Verify

After deployment, the witness URL is printed as a Terraform output. Test it:

```bash
WITNESS_URL=$(gcloud run services describe git-ratchet-witness \
  --region=us-central1 \
  --project=PROJECT \
  --format='value(status.url)')
curl -s "$WITNESS_URL/add-checkpoint"
```

A `method not allowed` response indicates that the witness is serving.
