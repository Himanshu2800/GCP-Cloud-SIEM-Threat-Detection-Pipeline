output "cloud_run_service_url" {
  description = "URL of the log-normalizer Cloud Run service"
  value       = data.google_cloud_run_service.log_normalizer.status[0].url
}

output "pubsub_topic_id" {
  description = "Full resource ID of the SIEM events Pub/Sub topic"
  value       = google_pubsub_topic.siem_events.id
}

output "pubsub_subscription_id" {
  description = "Full resource ID of the SIEM events Pub/Sub subscription"
  value       = google_pubsub_subscription.siem_events_sub.id
}

output "log_sink_name" {
  description = "Name of the Cloud Logging sink routing audit logs into Pub/Sub"
  value       = google_logging_project_sink.siem_sink.name
}

output "log_sink_writer_identity" {
  description = "Service identity used by the log sink to publish to Pub/Sub"
  value       = google_logging_project_sink.siem_sink.writer_identity
}
