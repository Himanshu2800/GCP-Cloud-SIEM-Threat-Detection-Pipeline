variable "project_id" {
  description = "GCP Project ID"
  type        = string
  default     = "cloud-siem-detection-lab"
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "asia-south2"
}

variable "zone" {
  description = "GCP Zone"
  type        = string
  default     = "asia-south2-b"
}
