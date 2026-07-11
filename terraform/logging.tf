resource "google_logging_project_sink" "siem_sink" {
  name        = "siem-log-sink"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.cloud_siem_events.id}"

  filter = <<-EOT
    log_id("cloudaudit.googleapis.com/activity") OR
    log_id("cloudaudit.googleapis.com/data_access") OR
    log_id("compute.googleapis.com/vpc_flows")
  EOT

  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "sink_publisher" {
  topic  = google_pubsub_topic.cloud_siem_events.name
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.siem_sink.writer_identity
}
