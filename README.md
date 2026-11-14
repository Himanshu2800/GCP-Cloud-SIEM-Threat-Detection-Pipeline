# GCP Cloud SIEM — Threat Detection Pipeline

A cloud-native detection-engineering pipeline built on GCP. Cloud Audit Log
and VPC Flow Log events flow through Pub/Sub into a Cloud Run service that normalizes,
enriches, and evaluates them against YAML detection rules, correlates
related findings across a short time window, indexes everything into
OpenSearch, and routes alerts to Slack/PagerDuty. A Grafana dashboard
sits on top for SOC-style triage.

This is a portfolio / detection-engineering project, not a production
SIEM. See [Known limitations](#known-limitations) below for what that
means concretely.

---

## Architecture

<img width="1024" height="1536" alt="image" src="https://github.com/user-attachments/assets/18d17996-9ab7-43a3-b753-8288ccead077" />

```
GCP Cloud Audit Logs (activity + data_access) + VPC Flow Logs
        │
        ▼
  Cloud Logging Sink  ──▶  Pub/Sub topic  ──▶  Pub/Sub push subscription
                                                       │
                                                       ▼
                                        Cloud Run service (Flask, cloud-functions/)
                                        normalize → enrich → detect → correlate
                                                       │
                              ┌────────────────────────┼───────────────────────┐
                              ▼                         ▼                       ▼
                        OpenSearch index         Slack / PagerDuty      Grafana dashboard
                        (raw + detections +          alert_router.py     (reads OpenSearch)
                         correlations)
```

---

## What's actually in this repo

- **Log sources**: GCP Cloud Audit Logs (admin activity + data access) and
  VPC Flow Logs. `normalizer.py` reads `protoPayload` for audit logs and
  `jsonPayload.connection` for flow logs, mapping both to the same flat
  schema (flow logs add `dest_ip`, `dest_port`, `bytes_sent`, `reporter`).
  There is no GKE audit log normalization implemented.
- **6 detection rules** (`cloud-functions/detections/*.yml`), each mapped
  to a MITRE ATT&CK technique — see the table below. Each rule has a
  stable `rule_id` (e.g. `GCP_VM_INSTANCE_DELETED`) independent of its
  human-readable `title`, so renaming a rule's display text never changes
  its identity for correlation sequences, test fixtures, or anything else
  keyed on it. `rule_loader.py` validates `rule_id` is UPPER_SNAKE_CASE
  and unique across all loaded rules.
- **A custom, Sigma-inspired rule engine** (`detector.py` + `rule_loader.py`),
  not `sigma-cli`. Rules support `condition_logic: AND/OR` over a list of
  `conditions`, each using one of four operators: `contains`, `equals`,
  `not_contains`, `greater_than` (numeric). `sigma-rules/` additionally holds true Sigma-syntax
  versions of the same 6 detections, kept for portability/documentation —
  the engine itself only reads `cloud-functions/detections/`.
- **A correlation engine** (`correlation.py`) that chains two findings by
  the same actor within a 15-minute window: IAM policy change → new
  service-account key, and firewall rule deletion → VM deletion. State is
  in-memory and process-local by design — this is documented in the code
  itself as a portfolio-scope limitation, not something the code pretends
  isn't there.
- **A regression test suite** (`cloud-functions/tests/`): `test_runner.py`
  checks 6 fixture events (5 rule-firing cases + 1 benign case)
  against `expected_results.json`, `test_flow_logs.py` runs the VPC Flow Log
  path end to end (normalize, enrich, detect; 9 cases including benign ones),
  and `test_correlation.py` separately
  covers the correlation engine with 6 sequential-event scenarios (both
  correlation rules firing, actor isolation, time-window enforcement, a
  missing precursor, and dedup on event replay). All three run in CI on every
  push/PR via `.github/workflows/tests.yml`, after a syntax check of every
  Python file.
- **A local replay demo** (`demo/replay_flow_log.py`) that sends a sample VPC
  flow log (plus benign variations) through the real Flask app with no GCP,
  OpenSearch or Slack needed. See [Local demo](#local-demo).
- **Terraform** for the GCP side (Pub/Sub, logging sink, and a GCE VM
  running OpenSearch/OpenSearch Dashboards/Grafana in Docker) — see
  `terraform/`.

---

## Detections

| Rule file | rule_id | MITRE Technique | Severity | Description |
|---|---|---|---|---|
| `gcp-iam-privilege-escalation.yml` | `GCP_IAM_POLICY_MODIFIED` | T1078 | HIGH | IAM policy modified via `setIamPolicy` |
| `gcp-service-account-key-created.yml` | `GCP_SERVICE_ACCOUNT_KEY_CREATED` | T1098.001 | HIGH | New service account key created |
| `gcp-bucket-made-public.yml` | `GCP_BUCKET_PERMISSIONS_MODIFIED` | T1530 | HIGH | Storage bucket IAM permissions modified (does not check for `allUsers`, so it detects permission changes, not public exposure) |
| `gcp-firewall-rule-deleted.yml` | `GCP_FIREWALL_RULE_DELETED` | T1562.007 | HIGH | VPC firewall rule deleted |
| `gcp-vm-instance-deleted.yml` | `GCP_VM_INSTANCE_DELETED` | T1485 | MEDIUM | Compute instance deleted |
| `gcp-large-egress-public-ip.yml` | `GCP_LARGE_EGRESS_PUBLIC_IP` | T1048 | HIGH | Single VPC flow record sending over 100 MB to a public IP |

`rule_id` is the stable identity used by findings, correlation
sequences, and test fixtures — `title` is display-only and can be
renamed freely without breaking anything.

Correlation rules (chained detections, see `correlation.py`) reference
the steps above by `rule_id`:

| Correlation | Sequence | Window | MITRE |
|---|---|---|---|
| Privilege Escalation via Key Creation | IAM Policy Modified → SA Key Created | 15 min | T1078 → T1098.001 |
| Firewall Removal Before VM Destruction | Firewall Rule Deleted → VM Instance Deleted | 15 min | T1562.007 → T1485 |

The T1078 mapping on IAM policy modification is a broad one (T1078 is
"Valid Accounts") — a `setIamPolicy` call is better thought of as a
precursor to privilege escalation/persistence than that technique itself.
Worth treating as a starting point to refine rather than a settled
mapping.

---

## Tech stack

| Layer | Technology |
|---|---|
| Log sources | GCP Cloud Audit Logs (admin activity + data access), VPC Flow Logs |
| Ingestion | Cloud Pub/Sub |
| Processing | Cloud Run (Flask, Python) |
| Detection | Custom Sigma-inspired YAML rule engine (not sigma-cli) |
| Storage | OpenSearch (self-hosted on a GCE VM via Docker) |
| Alerting | Slack webhook, PagerDuty Events API |
| Dashboard | Grafana + OpenSearch data source |
| Infra | Terraform |

---

## Repository structure

```
.
├── terraform/
│   ├── main.tf              # Pub/Sub topic/sub, logging sink (audit + flow logs), Cloud Run data source
│   ├── compute.tf           # GCE VM running OpenSearch/Dashboards/Grafana in Docker
│   ├── firewall.tf          # Firewall rules (SSH/Grafana limited to admin_source_ranges)
│   └── vpc.tf, variables.tf, providers.tf, outputs.tf
│
├── cloud-functions/         # The Cloud Run service
│   ├── main.py               # Flask entrypoint: Pub/Sub push handler
│   ├── normalizer.py         # Audit log + VPC flow log JSON -> normalized event
│   ├── enrichment.py         # resource_type, event_category, ip_classification, risk_score
│   ├── detector.py           # Rule evaluator (AND/OR, contains/equals/not_contains/greater_than)
│   ├── rule_loader.py        # Loads + validates YAML rules from detections/
│   ├── correlation.py        # Multi-event correlation (in-memory, actor-keyed)
│   ├── opensearch_client.py  # Indexing
│   ├── alert_router.py       # Routes findings to Slack/PagerDuty by severity
│   ├── pagerduty.py, alerter.py, config.py
│   ├── detections/           # 6 rules in the engine's own YAML format
│   ├── requirements.txt      # flask, requests, urllib3, pyyaml
│   └── tests/
│       ├── test_runner.py       # single-event detection regression tests
│       ├── test_correlation.py  # multi-event correlation regression tests
│       ├── test_flow_logs.py    # VPC flow log end-to-end tests
│       ├── expected_results.json
│       └── test_cases/       # 6 fixture events
│
├── demo/                     # Local replay demo (no cloud needed)
├── sigma-rules/              # Same 6 detections in true Sigma syntax (reference only)
├── docs/                     # Sample raw + normalized event JSON (audit + flow log)
├── .github/workflows/        # CI: syntax check + tests
├── screenshots/              # OpenSearch/Grafana/detection screenshots
└── LICENSE
```

---

## Quickstart

### Prerequisites

- GCP project with billing enabled, `gcloud` authenticated
- Terraform >= 1.6
- Python 3.11+
- Docker (runs on the provisioned GCE VM automatically via startup script)

### 1. Configure Terraform

```bash
cd terraform
# Create terraform.tfvars (not committed) with at least:
#   project_id          = "your-gcp-project-id"
#   admin_source_ranges = ["YOUR.IP.ADDRESS/32"]   # curl ifconfig.me
# admin_source_ranges is required and 0.0.0.0/0 is rejected by validation.
# Other variables and their defaults are in variables.tf.
```

### 2. Provision infrastructure

```bash
terraform init
terraform plan
terraform apply
```

This creates the Pub/Sub topic/subscription, the Cloud Audit Log sink,
and the GCE VM running OpenSearch, OpenSearch Dashboards, and Grafana.
The OpenSearch admin password is generated at boot time (not hardcoded) —
retrieve it with:

```bash
gcloud compute ssh soc-lab-vpc --zone <your-zone> \
  --command "sudo cat /opt/opensearch-admin-password.txt"
```

### 3. Deploy the Cloud Run service

```bash
cd cloud-functions
pip install -r requirements.txt --break-system-packages
gcloud run deploy log-normalizer \
  --source . \
  --region <your-region> \
  --set-env-vars OPENSEARCH_HOST=<vm-ip>,SLACK_WEBHOOK=<your-webhook>
```

Point the Pub/Sub push subscription at the deployed Cloud Run URL.

### 4. Import the Grafana dashboard / configure OpenSearch as needed

See `docs/` for sample raw and normalized event payloads, and
`screenshots/` for what the detections and dashboard look like once
running.

---

## Running tests

```bash
cd cloud-functions
pip install -r requirements.txt --break-system-packages
python3 tests/test_runner.py       # single-event detection tests
python3 tests/test_correlation.py  # multi-event correlation tests
python3 tests/test_flow_logs.py    # VPC flow log tests
```

None of these scripts need GCP or OpenSearch — they import the pure
logic modules (`normalizer.py`, `enrichment.py`, `detector.py`, `rule_loader.py`, `correlation.py`) directly.

`test_runner.py` runs 6 fixture events (5 that should fire a specific
rule, 1 benign/read-only event that should fire nothing) and diffs the
actual findings against `expected_results.json`.

`test_correlation.py` feeds sequences of events through the correlation
engine and checks: both correlation rules fire when their sequence
happens for the same actor within the time window; correlation does
NOT fire across different actors, outside the time window, or when only
one step of a sequence occurs; and a replayed/duplicate event doesn't
produce a second correlation for evidence already seen.

`test_flow_logs.py` wraps a sample flow log in a Pub/Sub envelope and checks
normalization, destination-IP enrichment, and detection: a 150 MB transfer to a
public IP fires `GCP_LARGE_EGRESS_PUBLIC_IP`, while a tiny transfer, a private
destination, a DEST-side duplicate record, and a non-numeric `bytes_sent` do not.

---

## Local demo

No GCP project, OpenSearch, Grafana or Slack needed. From the repo root:

```bash
pip install -r cloud-functions/requirements.txt
python3 demo/replay_flow_log.py    # on Windows: python demo\replay_flow_log.py
```

It sends a sample VPC flow log through the real Flask app, with indexing and
alerts replaced by printed lines. Expect one HIGH alert for the 150 MB transfer
to a public IP, and no alert for a 1 KB transfer, a private destination, or a
DEST-side duplicate record. This is a local replay, not a live deployment.

---

## Writing new detections

Add a YAML file to `cloud-functions/detections/`:

```yaml
title: GCP suspicious detection title
rule_id: GCP_SUSPICIOUS_DETECTION_TITLE   # UPPER_SNAKE_CASE, unique, stable
id: <uuid>
status: experimental
description: One sentence describing what this detects and why.
author: your-handle
date: YYYY-MM-DD
severity: HIGH   # LOW, MEDIUM, HIGH, CRITICAL
mitre:
  technique: T1XXX
condition_logic: AND   # or OR
conditions:
  - field: action
    operator: contains   # contains, equals, or not_contains
    value: some.method.Name
```

`rule_loader.py` validates required fields (including that `rule_id` is
UPPER_SNAKE_CASE and unique across all rules) and skips, with a logged
error, any rule that's malformed rather than crashing the whole load.
Add a matching fixture + expected-result entry (including the new
`rule_id`) under `cloud-functions/tests/` to cover it in the regression
suite — CI will run it automatically on the next push/PR.

---

## Known limitations

- **Detection operators are basic**: only `contains`, `equals`,
  `not_contains` and `greater_than` (numeric). No regex, field existence
  checks, or list matching yet.
- **Correlation state is in-memory and process-local** — it does not
  survive a Cloud Run cold start and is not shared across instances.
  A production version would back this with Redis or Firestore. This
  tradeoff is deliberate and documented in `correlation.py`.
- **Flow log detection is minimal**: one single-record rule (large egress
  to a public IP). Port-scan and beaconing detection need aggregation
  across records and are not implemented. The 100 MB threshold is
  untuned, and traffic to Google APIs via Private Google Access uses
  public IP ranges, so expect to tune for false positives. GKE audit
  logs are still not normalized.
- **Feedback-loop guard**: the logging sink in `terraform/main.tf` excludes
  flow records on port 9200 so the pipeline's own OpenSearch traffic is not
  re-ingested. That filter change has not been applied to a live project.
- **Flow-log detection has not been deployed.** It is covered by unit tests in
  CI and a local replay (`demo/`), but billing on the original GCP project has
  ended, so it has not seen real flow records.
- **Alerting gaps**: single-rule findings are not deduplicated, so a Pub/Sub
  redelivery re-sends the alert (only correlations are deduplicated). A
  malformed message returns HTTP 400, which Pub/Sub retries; a dead-letter
  topic would stop that.
- **Admin access depends on your IP**: SSH (22) and Grafana (3000) are limited
  to `admin_source_ranges`, a required variable that rejects `0.0.0.0/0`. If your
  ISP changes your IP you will need to update it (or use IAP for SSH).
  OpenSearch on port 9200 is limited to the internal subnet. These Terraform
  changes have not been through a live `terraform plan`.
- **MITRE mappings are a first pass**, not a rigorously reviewed
  mapping — see the note on T1078 above.
- **Terraform changes since the original deployment are unapplied.** The
  flow-log sink filter and later edits have not been through a `terraform
  plan`/`apply` against a live project (billing ended). The `.tf` files have
  been cross-checked for duplicate resources and broken references, which is
  not a substitute for an actual plan/apply before you rely on them. The
  Pub/Sub topic/subscription and logging sink are fully Terraform-owned; only
  the Cloud Run service is external, since its image is deployed via
  `gcloud run deploy`.

---

## License

MIT — use it, extend it, put it in your portfolio.
