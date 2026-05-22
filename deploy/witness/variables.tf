variable "project" {
  type        = string
  description = "GCP project ID to deploy into."
}

variable "region" {
  type        = string
  description = "GCP region for Cloud Run and GCS."
  default     = "us-central1"
}

variable "witness_name" {
  type        = string
  description = "Signer name for the witness (used in cosignature lines and vkeys)."
  default     = "git-ratchet-witness"
}
