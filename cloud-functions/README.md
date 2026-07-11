# Log-normalizer

Cloud Run function that processes GCP audit logs from Pub/Sub.

## What it does
1. Receives Pub/Sub messages containing raw GCP audit log JSON
2. Decodes and normalizes into a common schema
3. Runs 5 Sigma-based detection rules against the normalized event
4. Sends Slack alert if a detection fires
5. Indexes the normalized event into OpenSearch

## Environment Variables
| Variable | Description |
|---|---|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL for alerts |
| `OPENSEARCH_PASS` | OpenSearch admin password |
| `PORT` | Port to listen on (default 8080, set by Cloud Run) |

## Deployment
Deployed via Cloud Run in GCP (asia-south2 region).
Connected to `soc-lab-vpc` for internal OpenSearch access.
Triggered by Pub/Sub topic `cloud-siem-events`.
