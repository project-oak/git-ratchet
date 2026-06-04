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
