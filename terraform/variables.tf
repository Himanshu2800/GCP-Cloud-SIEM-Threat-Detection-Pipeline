variable "project_id" {
  description = "GCP project ID that hosts the SIEM pipeline"
  type        = string
}

variable "region" {
  description = "GCP region for regional resources (Cloud Run, etc.)"
  type        = string
  default     = "asia-south2"
}

variable "pubsub_topic_name" {
  description = "Name of the existing Pub/Sub topic that receives GCP audit log events"
  type        = string
  default     = "cloud-siem-events"
}

variable "pubsub_subscription_name" {
  description = "Name of the Pub/Sub subscription used to pull/push events to the log-normalizer"
  type        = string
  default     = "cloud-siem-events-sub"
}

variable "log_sink_name" {
  description = "Name of the Cloud Logging sink that routes audit logs into Pub/Sub"
  type        = string
  default     = "siem-audit-log-sink"
}

variable "cloud_run_service_name" {
  description = "Name of the existing Cloud Run service that normalizes and indexes logs"
  type        = string
  default     = "log-normalizer"
}
variable "zone" {
  description = "GCP compute zone for the SOC lab VM"
  type        = string
  default     = "asia-south2-a"
}

variable "admin_source_ranges" {
  description = "CIDR ranges allowed to reach SSH (22) and Grafana (3000) on the SOC lab VM, e.g. [\"203.0.113.7/32\"]. Required, and must not include 0.0.0.0/0."
  type        = list(string)

  validation {
    condition     = length(var.admin_source_ranges) > 0 && !contains(var.admin_source_ranges, "0.0.0.0/0")
    error_message = "admin_source_ranges must be non-empty and must not contain 0.0.0.0/0. Use your own IP, for example [\"YOUR.IP.ADDRESS/32\"]."
  }
}
