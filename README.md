# GCP Cloud SIEM — Threat Detection Pipeline

A cloud-native detection-engineering pipeline built on GCP. Cloud Audit Log
events flow through Pub/Sub into a Cloud Run service that normalizes,
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
GCP Cloud Audit Logs (activity + data_access)
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

- **Log source**: GCP Cloud Audit Logs (admin activity + data access) only.
  There is no VPC Flow Log or GKE audit log normalization implemented —
  the normalizer (`normalizer.py`) reads `protoPayload` fields specific to
  Cloud Audit Logs.
- **5 detection rules** (`cloud-functions/detections/*.yml`), each mapped
  to a MITRE ATT&CK technique — see the table below. Each rule has a
  stable `rule_id` (e.g. `GCP_VM_INSTANCE_DELETED`) independent of its
  human-readable `title`, so renaming a rule's display text never changes
  its identity for correlation sequences, test fixtures, or anything else
  keyed on it. `rule_loader.py` validates `rule_id` is UPPER_SNAKE_CASE
  and unique across all loaded rules.
- **A custom, Sigma-inspired rule engine** (`detector.py` + `rule_loader.py`),
  not `sigma-cli`. Rules support `condition_logic: AND/OR` over a list of
  `conditions`, each using one of three operators: `contains`, `equals`,
  `not_contains`. `sigma-rules/` additionally holds true Sigma-syntax
  versions of the same 5 detections, kept for portability/documentation —
  the engine itself only reads `cloud-functions/detections/`.
- **A correlation engine** (`correlation.py`) that chains two findings by
  the same actor within a 15-minute window: IAM policy change → new
  service-account key, and firewall rule deletion → VM deletion. State is
  in-memory and process-local by design — this is documented in the code
  itself as a portfolio-scope limitation, not something the code pretends
  isn't there.
- **A regression test suite** (`cloud-functions/tests/`): `test_runner.py`
  checks 8 fixture events (5 rule-firing cases + 3 negative/benign cases)
  against `expected_results.json`, and `test_correlation.py` separately
  covers the correlation engine with 6 sequential-event scenarios (both
  correlation rules firing, actor isolation, time-window enforcement, a
  missing precursor, and dedup on event replay). Both run in CI on every
  push/PR via `.github/workflows/tests.yml`.
- **Terraform** for the GCP side (Pub/Sub, logging sink, and a GCE VM
  running OpenSearch/OpenSearch Dashboards/Grafana in Docker) — see
  `terraform/`.

---

## Detections

| Rule file | rule_id | MITRE Technique | Severity | Description |
|---|---|---|---|---|
| `gcp-iam-privilege-escalation.yml` | `GCP_IAM_POLICY_MODIFIED` | T1078 | HIGH | IAM policy modified via `setIamPolicy` |
| `gcp-service-account-key-created.yml` | `GCP_SERVICE_ACCOUNT_KEY_CREATED` | T1098.001 | HIGH | New service account key created |
| `gcp-bucket-made-public.yml` | `GCP_BUCKET_PERMISSIONS_MODIFIED` | T1530 | HIGH | Storage bucket IAM permissions modified |
| `gcp-firewall-rule-deleted.yml` | `GCP_FIREWALL_RULE_DELETED` | T1562.007 | HIGH | VPC firewall rule deleted |
| `gcp-vm-instance-deleted.yml` | `GCP_VM_INSTANCE_DELETED` | T1485 | MEDIUM | Compute instance deleted |

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
| Log source | GCP Cloud Audit Logs (admin activity + data access) |
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
│   ├── main.tf              # Pub/Sub topic/sub, logging sink, Cloud Run data source
│   ├── compute.tf           # GCE VM running OpenSearch/Dashboards/Grafana in Docker
│   ├── firewall.tf          # Firewall rules (SSH/Grafana restricted to admin_source_ranges)
│   ├── vpc.tf, variables.tf, providers.tf, outputs.tf
│   └── terraform.tfvars.example
│
├── cloud-functions/         # The Cloud Run service
│   ├── main.py               # Flask entrypoint: Pub/Sub push handler
│   ├── normalizer.py         # Cloud Audit Log JSON -> normalized event
│   ├── enrichment.py         # resource_type, event_category, ip_classification, risk_score
│   ├── detector.py           # Rule evaluator (AND/OR, contains/equals/not_contains)
│   ├── rule_loader.py        # Loads + validates YAML rules from detections/
│   ├── correlation.py        # Multi-event correlation (in-memory, actor-keyed)
│   ├── opensearch_client.py  # Indexing
│   ├── alert_router.py       # Routes findings to Slack/PagerDuty by severity
│   ├── pagerduty.py, alerter.py, config.py
│   ├── detections/           # 5 rules in the engine's own YAML format
│   ├── requirements.txt      # flask, requests, urllib3, pyyaml
│   └── tests/
│       ├── test_runner.py       # single-event detection regression tests
│       ├── test_correlation.py  # multi-event correlation regression tests
│       ├── expected_results.json
│       └── test_cases/       # 8 fixture events
│
├── sigma-rules/              # Same 5 detections in true Sigma syntax (reference only)
├── docs/                     # Sample raw + normalized event JSON
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
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: set project_id, and set admin_source_ranges to
# YOUR IP (curl ifconfig.me) -- do not leave it as 0.0.0.0/0.
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
```

Neither script needs GCP, Flask, or OpenSearch — both import the pure
logic modules (`detector.py`, `rule_loader.py`, `correlation.py`) directly.

`test_runner.py` runs 8 fixture events (5 that should fire a specific
rule, 3 benign/read-only events that should fire nothing) and diffs the
actual findings against `expected_results.json`.

`test_correlation.py` feeds sequences of events through the correlation
engine and checks: both correlation rules fire when their sequence
happens for the same actor within the time window; correlation does
NOT fire across different actors, outside the time window, or when only
one step of a sequence occurs; and a replayed/duplicate event doesn't
produce a second correlation for evidence already seen.

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
  `not_contains`. No regex, field existence checks, numeric comparison,
  or list matching yet.
- **Correlation state is in-memory and process-local** — it does not
  survive a Cloud Run cold start and is not shared across instances.
  A production version would back this with Redis or Firestore. This
  tradeoff is deliberate and documented in `correlation.py`.
- **Only Cloud Audit Logs are ingested/normalized** — no VPC Flow Logs
  or GKE audit logs yet, despite that being a natural next step.
- **MITRE mappings are a first pass**, not a rigorously reviewed
  mapping — see the note on T1078 above.
- **Terraform has not been run through a live `terraform plan`/`apply`**
  against a real GCP project as part of this repo's validation — the
  `.tf` files have been manually cross-checked for duplicate resources,
  undeclared variables, and broken references, but that's not a
  substitute for an actual plan/apply cycle before you rely on it. The
  Pub/Sub topic/subscription and logging sink are fully Terraform-owned
  (created fresh on `apply`, not assumed to pre-exist); only the Cloud
  Run service is intentionally external, since its container image is
  deployed via `gcloud run deploy` rather than Terraform.

---

## License

MIT — use it, extend it, put it in your portfolio.
