# Terraform — SIEM Infrastructure Foundation

This directory codifies the ingestion foundation of the GCP Cloud SIEM
pipeline: the APIs it depends on, the Pub/Sub topic/subscription that carry
events, and the Cloud Logging sink that routes GCP audit activity into
Pub/Sub.

## What this does NOT do yet

- Does not manage the OpenSearch VM/Docker setup (treated separately for now).
- Does not deploy or manage the `log-normalizer` Cloud Run service's code —
  it's referenced as a **data source** (read-only) so Terraform can expose
  its URL as an output without risking a duplicate/conflicting deployment.
- Does not apply anything automatically — see the import note below before
  ever running `terraform apply`.

## ⚠️ Before running `terraform apply`

The Pub/Sub topic (`cloud-siem-events`), its subscription, and the Cloud
Logging sink almost certainly **already exist** in the GCP project, created
manually through the console. Terraform has no awareness of that — running
`apply` against this configuration as-is will attempt to create duplicates.

Before applying, import each existing resource into Terraform state:

```bash
terraform import google_pubsub_topic.siem_events projects/<project_id>/topics/cloud-siem-events
terraform import google_pubsub_subscription.siem_events_sub projects/<project_id>/subscriptions/cloud-siem-events-sub
terraform import google_logging_project_sink.siem_sink projects/<project_id>/sinks/siem-audit-log-sink
```

Then re-run `terraform plan` and confirm it shows **no changes** (or only
the changes you actually intend) before applying.

## Usage

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your real project_id

terraform init
terraform validate
terraform plan
```

`terraform plan` is as far as Day 13 goes. Do not `apply` until the existing
resources above have been imported.
