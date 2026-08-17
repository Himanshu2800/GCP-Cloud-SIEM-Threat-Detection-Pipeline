# -----------------------------------------------------------------------------
# APIs / Services required by the SIEM pipeline
# -----------------------------------------------------------------------------
resource "google_project_service" "run" {
  project            = var.project_id
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "pubsub" {
  project            = var.project_id
  service            = "pubsub.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "logging" {
  project            = var.project_id
  service            = "logging.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iam" {
  project            = var.project_id
  service            = "iam.googleapis.com"
  disable_on_destroy = false
}

# -----------------------------------------------------------------------------
# Pub/Sub -- ingestion transport between Cloud Logging and log-normalizer
#
# NOTE: These resources (cloud-siem-events topic + subscription) likely
# already exist in the project, created manually. Do NOT run `terraform
# apply` against this file until these are imported into Terraform state
# (see README.md) -- otherwise Terraform will attempt to create duplicates.
# -----------------------------------------------------------------------------
resource "google_pubsub_topic" "siem_events" {
  name    = var.pubsub_topic_name
  project = var.project_id

  depends_on = [google_project_service.pubsub]
}

resource "google_pubsub_subscription" "siem_events_sub" {
  name    = var.pubsub_subscription_name
  topic   = google_pubsub_topic.siem_events.name
  project = var.project_id

  ack_deadline_seconds = 20
}

# -----------------------------------------------------------------------------
# Cloud Logging -- routes relevant GCP activity into the Pub/Sub topic above.
# This is the actual SIEM ingestion path: GCP Activity -> Cloud Logging ->
# this sink -> Pub/Sub -> log-normalizer (Cloud Run).
#
# NOTE: Same import caveat as above -- this sink likely already exists.
# -----------------------------------------------------------------------------
resource "google_logging_project_sink" "siem_sink" {
  name        = var.log_sink_name
  project     = var.project_id
  destination = "pubsub.googleapis.com/${google_pubsub_topic.siem_events.id}"

  # Adjust this filter to match whatever log types your SIEM actually
  # ingests today (e.g. narrow to specific services/severities as needed).
  filter = "logName:\"cloudaudit.googleapis.com\""

  unique_writer_identity = true
}

# Grant the sink's writer identity permission to publish into the topic.
resource "google_pubsub_topic_iam_member" "sink_publisher" {
  topic  = google_pubsub_topic.siem_events.name
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.siem_sink.writer_identity
}

# -----------------------------------------------------------------------------
# Cloud Run -- log-normalizer service
#
# This references the EXISTING service as a data source rather than managing
# it as a resource yet. Deploying/managing the container image via Terraform
# is a Day 14+ step once the service is imported and the team is comfortable
# letting Terraform own deployments.
# -----------------------------------------------------------------------------
data "google_cloud_run_service" "log_normalizer" {
  name     = var.cloud_run_service_name
  location = var.region
  project  = var.project_id

  depends_on = [google_project_service.run]
}
