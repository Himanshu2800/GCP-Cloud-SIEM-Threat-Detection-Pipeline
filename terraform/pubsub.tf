resource "google_pubsub_topic" "cloud_siem_events" {
  name = "cloud-siem-events"
}

resource "google_pubsub_subscription" "cloud_siem_subscription" {
  name  = "cloud-siem-events-sub"
  topic = google_pubsub_topic.cloud_siem_events.name

  ack_deadline_seconds = 20
}
