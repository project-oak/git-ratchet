# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "7.32.0"
    }
  }
}

provider "google" {
  project = var.project
  region  = var.region
}

# --- GCS bucket for witness state + origins ---

resource "google_storage_bucket" "witness" {
  name                        = "${var.project}-git-ratchet-witness"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
}

resource "google_storage_bucket_object" "origins" {
  name   = "origins"
  bucket = google_storage_bucket.witness.name
  source = "${path.module}/origins"
}

# --- Artifact Registry for the witness container image ---

resource "google_artifact_registry_repository" "witness" {
  location      = var.region
  repository_id = "git-ratchet"
  format        = "DOCKER"
  description   = "git-ratchet witness container images"
}

# --- Service account for Cloud Run ---

resource "google_service_account" "witness" {
  account_id   = "git-ratchet-witness"
  display_name = "git-ratchet witness"
}

resource "google_storage_bucket_iam_member" "witness_bucket" {
  bucket = google_storage_bucket.witness.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.witness.email}"
}

resource "google_kms_crypto_key_iam_member" "witness_signer" {
  crypto_key_id = google_kms_crypto_key.witness.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.witness.email}"
}

# --- KMS key ring and signing key ---

resource "google_kms_key_ring" "witness" {
  name     = "git-ratchet-witness"
  location = var.region
}

resource "google_kms_crypto_key" "witness" {
  name     = "witness-signing-key"
  key_ring = google_kms_key_ring.witness.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_ED25519"
    protection_level = "SOFTWARE"
  }
}

# --- Cloud Run service ---

resource "google_cloud_run_v2_service" "witness" {
  depends_on          = [google_storage_bucket_object.origins]
  name                = "git-ratchet-witness"
  location            = var.region
  deletion_protection = false

  template {
    scaling {
      max_instance_count = 1
    }

    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
    service_account       = google_service_account.witness.email

    volumes {
      name = "data"
      gcs {
        bucket    = google_storage_bucket.witness.name
        read_only = false
      }
    }

    containers {
      image = "${var.region}-docker.pkg.dev/${var.project}/${google_artifact_registry_repository.witness.repository_id}/witness:latest"

      args = [
        "--addr=:8080",
        "--kms-key=${google_kms_crypto_key.witness.id}/cryptoKeyVersions/1",
        "--name=${var.witness_name}",
        "--origins-file=/data/origins",
        "--state-file=/data/witness-state.json",
      ]

      ports {
        container_port = 8080
      }

      volume_mounts {
        name       = "data"
        mount_path = "/data"
      }
    }
  }
}

# --- Allow unauthenticated access (witness authenticates via origin signatures) ---

resource "google_cloud_run_v2_service_iam_member" "public" {
  project  = var.project
  location = var.region
  name     = google_cloud_run_v2_service.witness.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# --- Outputs ---

output "witness_url" {
  description = "The URL of the deployed witness service."
  value       = google_cloud_run_v2_service.witness.uri
}

output "bucket_name" {
  description = "The GCS bucket for witness state and keys."
  value       = google_storage_bucket.witness.name
}

output "registry" {
  description = "The Artifact Registry repository path."
  value       = "${var.region}-docker.pkg.dev/${var.project}/${google_artifact_registry_repository.witness.repository_id}"
}

output "kms_key" {
  description = "The KMS CryptoKeyVersion resource name for the witness signing key."
  value       = "${google_kms_crypto_key.witness.id}/cryptoKeyVersions/1"
}
