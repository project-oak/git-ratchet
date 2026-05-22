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

# --- KMS key ring and origin signing key ---

resource "google_kms_key_ring" "origin" {
  name     = "git-ratchet-origin"
  location = var.region
}

resource "google_kms_crypto_key" "origin" {
  name     = "origin-signing-key"
  key_ring = google_kms_key_ring.origin.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_ED25519"
    protection_level = "SOFTWARE"
  }
}

# --- Outputs ---

output "kms_key" {
  description = "The KMS CryptoKeyVersion resource name for the origin signing key."
  value       = "${google_kms_crypto_key.origin.id}/cryptoKeyVersions/1"
}
