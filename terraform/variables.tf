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
