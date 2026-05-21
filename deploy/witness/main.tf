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

# --- GCS bucket for witness state + keys ---

resource "google_storage_bucket" "witness" {
  name                        = "${var.project}-git-ratchet-witness"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
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

# --- Cloud Run service ---

resource "google_cloud_run_v2_service" "witness" {
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
        "--key=/data/witness-key",
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
