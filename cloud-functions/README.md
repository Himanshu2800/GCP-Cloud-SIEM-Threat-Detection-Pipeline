# Log Normalizer

Cloud Run service that processes GCP audit logs delivered through Pub/Sub.

## What It Does

1. Receives Pub/Sub messages containing raw GCP audit log JSON
2. Decodes and normalizes events into a common schema
3. Runs 5 Sigma-based detection rules against each normalized event
4. Indexes the normalized event into OpenSearch
5. Sends a Slack alert for each detection rule that fires

## Structure

* `main.py` — Flask entry point and processing pipeline orchestration
* `normalizer.py` — Pub/Sub payload decoding and GCP audit log normalization
* `detector.py` — Detection rule definitions and evaluation
* `opensearch_client.py` — OpenSearch indexing
* `alerter.py` — Slack alert formatting and delivery
* `config.py` — Runtime configuration

## Environment Variables

| Variable            | Description                                                                       |
| ------------------- | ----------------------------------------------------------------------------------|
| `SLACK_WEBHOOK_URL`  | Slack incoming webhook URL for alerts                                             |
| `OPENSEARCH_PASS`    | OpenSearch admin password                                                         |
| `PORT`               | Port to listen on. Defaults to `8080` for local execution and is set by Cloud Run |

## Deployment

Deployed via Cloud Run in GCP (`asia-south2` region).
Connected to `soc-lab-vpc` for internal OpenSearch access.
Receives events from the Pub/Sub topic `cloud-siem-events`.
