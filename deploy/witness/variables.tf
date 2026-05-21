variable "project" {
  type        = string
  description = "GCP project ID to deploy into."
}

variable "region" {
  type        = string
  description = "GCP region for Cloud Run and GCS."
  default     = "us-central1"
}
