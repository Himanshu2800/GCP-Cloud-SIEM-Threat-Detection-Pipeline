# GCP Cloud SIEM — Threat Detection Pipeline

A cloud-native Security Information and Event Management (SIEM) system built entirely on GCP. Ingests logs from Cloud Audit, VPC Flow, Firewall, and GKE sources, normalizes and enriches them, runs Sigma detection rules mapped to MITRE ATT&CK, and delivers real-time alerts to Slack/PagerDuty with a Grafana dashboard for SOC analysts.

---

## Architecture

<img width="1024" height="1536" alt="image" src="https://github.com/user-attachments/assets/18d17996-9ab7-43a3-b753-8288ccead077" />


---

## Features

- **Multi-source log ingestion** — Cloud Audit (admin + data access), VPC Flow, Firewall rules, GKE workloads, and IAM events
- **Normalized event schema** — all sources flattened into a common structure for consistent querying
- **Sigma-based detections** — 10+ production-grade rules covering privilege escalation, exfiltration, defense evasion, and lateral movement
- **MITRE ATT&CK mapping** — every detection tagged with technique IDs (e.g. T1098, T1537)
- **Real-time alerting** — Slack messages and PagerDuty incidents fire within seconds of detection
- **Grafana SOC dashboard** — events per hour, top principals, alert timeline, detection heatmap by tactic
- **Infrastructure as code** — entire GCP setup provisioned with Terraform

---

## Tech Stack

| Layer | Technology |
|---|---|
| Log sources | GCP Cloud Logging (Audit, VPC Flow, Firewall, GKE) |
| Ingestion | Cloud Pub/Sub |
| Processing | Cloud Functions (Python 3.11) |
| Detection | Sigma rules + `sigma-cli` |
| Storage | OpenSearch 2.x (self-hosted on GCE) |
| Alerting | Slack Webhooks, PagerDuty Events API v2 |
| Dashboard | Grafana 10 + OpenSearch data source |
| Infra | Terraform 1.6+ |
| CI/CD | GitHub Actions |

---

## Repository Structure

```
gcp-siem/
├── terraform/
│   ├── main.tf               # Core GCP resources
│   ├── pubsub.tf             # Pub/Sub topic + subscription
│   ├── log_sinks.tf          # Cloud Logging sinks → Pub/Sub
│   ├── cloud_function.tf     # Function deployment config
│   ├── iam.tf                # Service account + IAM bindings
│   └── variables.tf
│
├── functions/
│   ├── processor/
│   │   ├── main.py           # Entry point — pull, normalize, detect, index
│   │   ├── normalizer.py     # Raw GCP log → common schema
│   │   ├── detector.py       # Sigma rule runner
│   │   ├── enricher.py       # GeoIP, asset context
│   │   ├── alerter.py        # Slack + PagerDuty dispatch
│   │   └── requirements.txt
│   └── tests/
│       ├── test_normalizer.py
│       ├── test_detector.py
│       └── fixtures/         # Sample raw GCP log payloads
│
├── detections/               # Sigma rules (one file per detection)
│   ├── gcp_iam_privilege_escalation.yml
│   ├── gcp_service_account_key_created.yml
│   ├── gcp_bucket_made_public.yml
│   ├── gcp_firewall_rule_deleted.yml
│   ├── gcp_impossible_travel.yml
│   ├── gcp_excessive_api_calls.yml
│   ├── gcp_new_region_compute.yml
│   ├── gcp_iam_policy_on_non_ci_principal.yml
│   ├── gcp_data_exfil_large_object_download.yml
│   └── gcp_service_account_impersonation.yml
│
├── dashboards/
│   └── grafana_siem_dashboard.json   # Import-ready Grafana JSON
│
├── opensearch/
│   └── index_template.json           # Field mappings for normalized events
│
├── scripts/
│   ├── bootstrap.sh          # First-time setup helper
│   └── test_detection.py     # Fire a synthetic event to test end-to-end
│
├── docs/
│   ├── detections.md         # Full write-up of each rule + MITRE mapping
│   ├── setup_gcp.md          # GCP project prerequisites
│   └── runbook.md            # How to triage an alert
│
└── README.md
```

---

## Detections

All rules live in `detections/` as Sigma YAML. Each one is mapped to one or more MITRE ATT&CK techniques.

| Rule | MITRE Technique | Severity | Description |
|---|---|---|---|
| `gcp_iam_privilege_escalation` | T1098 | Critical | IAM policy set by a non-CI/CD principal |
| `gcp_service_account_key_created` | T1098.001 | High | New service account key created — persistent access vector |
| `gcp_bucket_made_public` | T1537 | Critical | Cloud Storage bucket ACL changed to `allUsers` |
| `gcp_firewall_rule_deleted` | T1562.004 | High | VPC firewall rule removed — potential defense evasion |
| `gcp_impossible_travel` | T1078 | High | Same principal authenticated from two countries within 1 hour |
| `gcp_excessive_api_calls` | T1046 | Medium | >50 API calls from a single principal in a 60-second window |
| `gcp_new_region_compute` | T1578 | Medium | Compute instance created in a region with no prior usage |
| `gcp_iam_policy_on_non_ci_principal` | T1098 | High | SetIamPolicy called outside of known automation accounts |
| `gcp_data_exfil_large_object_download` | T1530 | High | Large GCS object downloaded by an external IP |
| `gcp_service_account_impersonation` | T1134 | High | `iam.serviceAccounts.actAs` granted to a user account |

---

## Quickstart

### Prerequisites

- GCP project with billing enabled
- `gcloud` CLI authenticated (`gcloud auth application-default login`)
- Terraform >= 1.6
- Python 3.11+
- OpenSearch instance running (see `docs/setup_gcp.md`)

### 1. Clone and configure

```bash
git clone https://github.com/yourusername/gcp-siem.git
cd gcp-siem
cp terraform/variables.tf.example terraform/variables.tf
# Edit variables.tf — fill in your project ID, region, Slack webhook URL
```

### 2. Provision GCP infrastructure

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

This creates the log sinks, Pub/Sub topic and subscription, Cloud Function, and required IAM bindings.

### 3. Deploy the processor function

```bash
cd functions/processor
pip install -r requirements.txt
gcloud functions deploy siem-processor \
  --runtime python311 \
  --trigger-topic siem-events \
  --entry-point process_event \
  --set-env-vars OPENSEARCH_HOST=<your-host>,SLACK_WEBHOOK=<your-webhook>
```

### 4. Import the Grafana dashboard

In Grafana, go to Dashboards → Import → Upload JSON and select `dashboards/grafana_siem_dashboard.json`. Set the OpenSearch data source when prompted.

### 5. Test end-to-end

```bash
python scripts/test_detection.py --rule gcp_bucket_made_public
# Should fire within ~10 seconds in Slack
```

---

## Normalized Event Schema

Every log source is normalized to this common schema before detection and indexing:

```json
{
  "timestamp": "2025-08-14T10:23:45Z",
  "event_id": "uuid-v4",
  "source": "cloudaudit",
  "principal": "user@example.com",
  "source_ip": "102.45.67.89",
  "source_country": "NG",
  "action": "storage.buckets.setIamPolicy",
  "resource_type": "gcs_bucket",
  "resource_name": "projects/my-project/buckets/prod-data",
  "project_id": "my-project",
  "severity": "WARNING",
  "mitre_techniques": ["T1537"],
  "mitre_tactics": ["exfiltration"],
  "sigma_rule_id": "gcp_bucket_made_public",
  "alert": true,
  "raw": { ... }
}
```

---

## Alert Example

When a detection fires, Slack receives a structured message:

```
🚨 CRITICAL — GCP bucket made public
─────────────────────────────────────
Rule:       gcp_bucket_made_public
MITRE:      T1537 — Transfer Data to Cloud Account
Principal:  admin@example.com
Resource:   gs://prod-data-backup
Project:    my-gcp-project
Source IP:  102.45.67.89 (Nigeria)
Time:       2025-08-14 10:23:45 UTC

[View in Dashboard]  [Open Runbook]
```

---

## Running Tests

```bash
cd functions
python -m pytest tests/ -v
```

Test fixtures in `tests/fixtures/` contain real-shaped (anonymized) GCP log payloads for each source type so you can develop and test rules without a live GCP project.

---

## Writing New Detections

Add a new Sigma rule to `detections/`:

```yaml
title: GCP suspicious detection title
id: <generate a UUID>
status: experimental
description: One sentence describing what this detects and why it matters.
author: your-github-handle
date: YYYY/MM/DD
logsource:
    product: gcp
    service: cloudaudit         # or vpc_flow, firewall, gke
detection:
    selection:
        action: 'MethodName'    # exact GCP API method
    filter_known_good:
        principal|contains: 'terraform-sa@'
    condition: selection and not filter_known_good
falsepositives:
    - Legitimate automation via CI/CD pipelines
level: high                    # informational, low, medium, high, critical
tags:
    - attack.tactic_name
    - attack.T1XXX
```

Then run `python scripts/test_detection.py --rule <your_rule_filename>` to validate it fires on a synthetic matching event.

---

## Roadmap

- [ ] Pub/Sub dead-letter queue for failed processing
- [ ] Dataflow pipeline for high-volume environments (replace Cloud Function)
- [ ] BigQuery sink for long-term log retention and threat hunting
- [ ] Automated MITRE ATT&CK Navigator layer export from active detections
- [ ] Slack bot for `/investigate <principal>` lookups from the alert message
- [ ] Terraform module for multi-project log aggregation

---

## Cost Estimate (small GCP project)

| Resource | Estimated monthly cost |
|---|---|
| Cloud Logging + Log Sink | ~$0–$5 |
| Pub/Sub | ~$0–$2 |
| Cloud Functions (invocations) | ~$0–$3 |
| GCE VM for OpenSearch (e2-standard-2) | ~$50–$70 |
| Grafana (self-hosted on same VM) | $0 |
| **Total** | **~$55–$80/month** |

Use a `e2-micro` for dev/testing — OpenSearch will be slow but functional and drops cost to ~$10/month.

---

## Resources

- [Sigma rules documentation](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK — Cloud matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [GCP Cloud Logging log fields reference](https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry)
- [OpenSearch index mapping docs](https://opensearch.org/docs/latest/field-types/)
- [GCP security best practices](https://cloud.google.com/security/best-practices)

---

## License

MIT — use it, extend it, put it in your portfolio.
