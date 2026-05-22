variable "project" {
  type        = string
  description = "GCP project ID to deploy into."
}

variable "region" {
  type        = string
  description = "GCP region for KMS."
  default     = "us-central1"
}
