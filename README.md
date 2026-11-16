GCP Cloud SIEM — Threat Detection Pipeline
A cloud-native detection-engineering pipeline built on GCP. Cloud Audit Log
and VPC Flow Log events flow through Pub/Sub into a Cloud Run service that normalizes,
enriches, and evaluates them against YAML detection rules, correlates
related findings across a short time window, indexes everything into
OpenSearch, and routes alerts to Slack/PagerDuty. A Grafana dashboard
sits on top for SOC-style triage.

Built as a hands-on cloud-security portfolio project, this repository demonstrates
log processing, detection-as-code, event correlation, and alert routing.
The local detection logic is tested; cloud deployment still requires manual
configuration and validation. See Validation status and
Known limitations.
Validation status
Component	Current status
Audit-log detection logic	Six local regression checks pass: five detection cases and one benign case
Correlation logic	Six local checks pass; state and deduplication remain process-local
VPC Flow Log logic	Nine local checks pass; live flow-log ingestion has not been validated
Local Flask replay	Included; replaces indexing and alert delivery with local stubs
CI	Runs the three test scripts on pushes to main and pull requests targeting main
Cloud deployment	Earlier lab deployment documented in screenshots; current infrastructure changes have not been validated with a live plan/apply


Passing these 21 checks verifies the supplied fixtures, not cloud connectivity,
alert delivery, detection accuracy on real traffic, or production readiness.
The original project's billing has ended, so recent flow-log and infrastructure
changes remain locally tested or unvalidated, as noted below.
Architecture
<img width="1024" height="1536" alt="GCP cloud SIEM pipeline architecture" src="https://github.com/user-attachments/assets/18d17996-9ab7-43a3-b753-8288ccead077" />```mermaid
flowchart TD
    A[Cloud Audit Logs and VPC Flow Logs] --> B[Cloud Logging sink]
    B --> C[Pub/Sub topic and push subscription]
    C --> D[Cloud Run: normalize, enrich, detect, correlate]
    D --> E[OpenSearch]
    D --> F[Slack and PagerDuty]
    E --> G[Grafana triage dashboard]
```
This is the intended end-to-end data path. The checked-in Terraform does not
configure the subscription's push endpoint or all Cloud Run connectivity and IAM
requirements; see Cloud deployment status.
What's actually in this repo
- Log sources: GCP Cloud Audit Logs (admin activity + data access) and
  VPC Flow Logs. normalizer.py reads protoPayload for audit logs and
  jsonPayload.connection for flow logs, mapping both to the same flat
  schema (flow logs add dest_ip, dest_port, bytes_sent, reporter).
  There is no GKE audit log normalization implemented.
- 6 detection rules (cloud-functions/detections/*.yml), each mapped
  to a MITRE ATT&CK technique — see the table below. Each rule has a
  stable rule_id (e.g. GCP_VM_INSTANCE_DELETED) independent of its
  human-readable title, so renaming a rule's display text never changes
  its identity for correlation sequences, test fixtures, or anything else
  keyed on it. rule_loader.py validates rule_id is UPPER_SNAKE_CASE
  and logs duplicate IDs; it does not reject duplicate rules.
- A custom, Sigma-inspired rule engine (detector.py + rule_loader.py),
  not sigma-cli. Rules support condition_logic: AND/OR over a list of
  conditions, each using one of four operators: contains, equals,
  not_contains, greater_than (numeric). sigma-rules/ additionally holds true Sigma-syntax
  versions of the same 6 detections, kept for portability/documentation —
  the engine itself only reads cloud-functions/detections/.
- A correlation engine (correlation.py) that chains two findings by
  the same actor within a 15-minute window: IAM policy change → new
  service-account key, and firewall rule deletion → VM deletion. State is
  in-memory and process-local, so it is not shared between workers or instances.
- A regression test suite (cloud-functions/tests/): test_runner.py
  checks 6 fixture events (5 rule-firing cases + 1 benign case)
  against expected_results.json, test_flow_logs.py runs the VPC Flow Log
  path end to end (normalize, enrich, detect; 9 cases including benign ones),
  and test_correlation.py separately
  covers the correlation engine with 6 sequential-event scenarios (both
  correlation rules firing, actor isolation, time-window enforcement, a
  missing precursor, and dedup on event replay). All three run in CI on pushes to main and pull requests targeting
  main via .github/workflows/tests.yml. There is no separate syntax-check step.
- A local replay demo (demo/replay_flow_log.py) that sends a sample VPC
  flow log (plus benign variations) through the real Flask app with no GCP,
  OpenSearch or Slack needed. See Quickstart: local demo.
- Terraform for the GCP side (Pub/Sub, logging sink, and a GCE VM
  running OpenSearch/OpenSearch Dashboards/Grafana in Docker) — see
  terraform/.
Detections
Rule file	rule_id	MITRE Technique	Severity	Description
gcp-iam-privilege-escalation.yml	GCP_IAM_POLICY_MODIFIED	T1078	HIGH	IAM policy modified via setIamPolicy
gcp-service-account-key-created.yml	GCP_SERVICE_ACCOUNT_KEY_CREATED	T1098.001	HIGH	New service account key created
gcp-bucket-made-public.yml	GCP_BUCKET_PERMISSIONS_MODIFIED	T1530	HIGH	Storage bucket IAM permissions modified (does not check for allUsers, so it detects permission changes, not public exposure)
gcp-firewall-rule-deleted.yml	GCP_FIREWALL_RULE_DELETED	T1562.007	HIGH	VPC firewall rule deleted
gcp-vm-instance-deleted.yml	GCP_VM_INSTANCE_DELETED	T1485	MEDIUM	Compute instance deleted
gcp-large-egress-public-ip.yml	GCP_LARGE_EGRESS_PUBLIC_IP	T1048	HIGH	Single VPC flow record sending over 100 MB to a public IP


rule_id is the stable identity used by findings, correlation
sequences, and test fixtures — title is display-only and can be
renamed freely without breaking anything.

Correlation rules (chained detections, see correlation.py) reference
the steps above by rule_id:
Correlation	Sequence	Window	MITRE
Privilege Escalation via Key Creation	IAM Policy Modified → SA Key Created	15 min	T1078 → T1098.001
Firewall Removal Before VM Destruction	Firewall Rule Deleted → VM Instance Deleted	15 min	T1562.007 → T1485


The T1078 mapping on IAM policy modification is a broad one (T1078 is
"Valid Accounts") — a setIamPolicy call is better thought of as a
precursor to privilege escalation/persistence than that technique itself.
Worth treating as a starting point to refine rather than a settled
mapping.
Tech stack
Layer	Technology
Log sources	GCP Cloud Audit Logs (admin activity + data access), VPC Flow Logs
Ingestion	Cloud Pub/Sub
Processing	Cloud Run (Flask, Python)
Detection	Custom Sigma-inspired YAML rule engine (not sigma-cli)
Storage	OpenSearch (self-hosted on a GCE VM via Docker)
Alerting	Slack webhook, PagerDuty Events API
Dashboard	Grafana + OpenSearch data source
Infra	Terraform


Repository structure
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
├── .github/workflows/        # CI: three regression test scripts
├── screenshots/              # OpenSearch/Grafana/detection screenshots
└── LICENSE
Quickstart: local demo
Python 3.11+ is recommended. From the repository root, create a virtual
environment and install the dependencies:
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell instead:
# .venv\Scripts\Activate.ps1
python -m pip install -r cloud-functions/requirements.txt
python demo/replay_flow_log.py
The demo sends four sample events through the Flask handler. Expect one HIGH
finding for 150 MB sent to a public IP, and no findings for the small transfer,
private destination, or DEST-side record. OpenSearch and alert delivery are
stubbed, so no cloud account or external credentials are needed.
Cloud deployment status
The repository is not yet a complete fresh-project deployment recipe.
Terraform defines Pub/Sub, the logging sink, a VPC, firewall rules, and a GCE VM
with Docker startup commands. It references an existing Cloud Run service
through a data source; it does not deploy that service.

Before attempting a live deployment, complete the following integration steps:
1. Prepare the project and service. Configure billing, authentication, required
   APIs, and permissions. Establish the Cloud Run service named by
   cloud_run_service_name before a full Terraform plan, or update Terraform
   to manage it. The previous apply-first quickstart does not work for an empty
   project with the current data source.
2. Configure Terraform. Supply project_id and admin_source_ranges in an
   uncommitted terraform.tfvars. Set region and zone as needed. The provider
   file requires Terraform >= 1.5. Import existing topic, subscription, and sink
   resources before applying to an existing lab; see terraform/README.md.
3. Correct the VM startup configuration. terraform/compute.tf currently
   contains a hardcoded OpenSearch initial password. Replace that credential
   setup before deployment. It does not generate a password file at boot.
   Validate container networking, OpenSearch/Dashboards connectivity, compatible
   image versions, and persistent storage; the startup commands alone do not
   establish a verified working stack.
4. Configure the application. Replace the placeholder OpenSearch URL and
   username in cloud-functions/config.py, and supply the environment variables
   listed below. Establish private connectivity from Cloud Run to OpenSearch;
   the firewall rule allowing the internal subnet does not establish that path.
5. Configure authenticated Pub/Sub push delivery. Once Cloud Run is deployed,
   set the subscription's push endpoint to its service URL. Configure a push
   authentication service account, grant it permission to invoke the service,
   and configure the required token-signing permissions. The Terraform
   subscription currently has no push_config or associated invocation IAM.
   Capture this configuration in Terraform to avoid unmanaged drift.
6. Validate ingestion and triage. Check the required audit-log settings and
   VPC Flow Log generation, sink publishing permissions, authenticated delivery,
   indexing, and Slack/PagerDuty receipt using controlled test events. Configure
   Grafana's OpenSearch data source and build the dashboard from the examples;
   the repository includes screenshots, not an importable dashboard definition.
Current application configuration
Setting	How the current code reads it
OpenSearch URL	OPENSEARCH_URL constant in cloud-functions/config.py; currently a placeholder
OpenSearch username	OPENSEARCH_USER constant in the same file; currently a placeholder
OpenSearch password	OPENSEARCH_PASS environment variable
OpenSearch index	INDEX_NAME constant; defaults to gcp-audit-logs
Slack webhook	SLACK_WEBHOOK_URL environment variable
PagerDuty integration key	PAGERDUTY_ROUTING_KEY environment variable; paging is skipped if unset


OPENSEARCH_HOST and SLACK_WEBHOOK are not read by the current application.
Keep real credentials out of source control. Deployment commands and infrastructure
changes need live validation after these gaps are resolved.
Running tests
cd cloud-functions
python -m pip install -r requirements.txt
python3 tests/test_runner.py       # single-event detection tests
python3 tests/test_correlation.py  # multi-event correlation tests
python3 tests/test_flow_logs.py    # VPC flow log tests
None of these scripts need GCP or OpenSearch — they import the pure
logic modules (normalizer.py, enrichment.py, detector.py, rule_loader.py, correlation.py) directly.

test_runner.py runs 6 fixture events (5 that should fire a specific
rule, 1 benign/read-only event that should fire nothing) and diffs the
actual findings against expected_results.json.

test_correlation.py feeds sequences of events through the correlation
engine and checks: both correlation rules fire when their sequence
happens for the same actor within the time window; correlation does
NOT fire across different actors, outside the time window, or when only
one step of a sequence occurs; and a replayed/duplicate event doesn't
produce a second correlation for evidence already seen.

test_flow_logs.py wraps a sample flow log in a Pub/Sub envelope and checks
normalization, destination-IP enrichment, and detection: a 150 MB transfer to a
public IP fires GCP_LARGE_EGRESS_PUBLIC_IP, while a tiny transfer, a private
destination, a DEST-side duplicate record, and a non-numeric bytes_sent do not.
Writing new detections
Add a YAML file to cloud-functions/detections/:
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
    operator: contains   # contains, equals, not_contains, or greater_than
    value: some.method.Name
rule_loader.py checks required fields, the rule_id format, condition
logic, and supported operators. Rules that fail these checks are skipped with
an error. Duplicate rule IDs are logged but still loaded, so ensure uniqueness
when adding rules.
Add a matching fixture + expected-result entry (including the new
rule_id) under cloud-functions/tests/ to cover it in the regression
suite — CI will run it automatically on the next push/PR.
Known limitations
- Detection operators are basic: only contains, equals,
  not_contains and greater_than (numeric). No regex, field existence
  checks, or list matching yet.
- Correlation state is in-memory and process-local — it does not
  survive a Cloud Run cold start and is not shared across instances.
  Shared, durable state is needed for correlation across workers and instances.
  Late-arriving precursor events are not retrospectively matched. Correlation
  fingerprints omit actor identity, so equal-timestamp sequences from different
  actors can collide; the deduplication set also has no expiration.
- Flow log detection is minimal: one single-record rule (large egress
  to a public IP). Port-scan and beaconing detection need aggregation
  across records and are not implemented. The 100 MB threshold is
  untuned, and traffic to Google APIs via Private Google Access uses
  public IP ranges, so expect to tune for false positives. GKE audit
  logs are still not normalized.
- Feedback-loop guard: the logging sink in terraform/main.tf excludes
  flow records on port 9200 so the pipeline's own OpenSearch traffic is not
  re-ingested. That filter change has not been applied to a live project.
- Flow-log detection has not been deployed. It is covered by unit tests in
  CI and a local replay (demo/), but billing on the original GCP project has
  ended, so it has not seen real flow records.
- Alerting gaps: single-rule findings are not deduplicated, so a Pub/Sub
  redelivery re-sends the alert (only correlations are deduplicated). A
  malformed message returns HTTP 400, which Pub/Sub retries; a dead-letter
  policy and correctly configured dead-letter topic are not included.
- Delivery is best-effort: indexing and alert clients log failures without
  propagating them to the handler, which can still acknowledge the message with
  HTTP 200. Failed writes or alerts can therefore be lost. OpenSearch requests
  disable TLS certificate verification and have no explicit request timeout.
- Detection fidelity is limited: sensitive administrative actions can be
  legitimate. IAM policy modification does not prove privilege escalation,
  and bucket permission modification does not prove public access. The current
  rules need additional context and tuning before operational use.
- Admin access depends on your IP: SSH (22) and Grafana (3000) are limited
  to admin_source_ranges, a required variable that rejects 0.0.0.0/0. If your
  ISP changes your IP you will need to update it (or use IAP for SSH).
  OpenSearch on port 9200 is limited to the internal subnet. These Terraform
  changes have not been through a live terraform plan.
- MITRE mappings are a first pass, not a rigorously reviewed
  mapping — see the note on T1078 above.
- Terraform changes since the original deployment are unapplied. The
  flow-log sink filter and later edits have not been through a terraform plan/`apply` against a live project (billing ended). The topic, subscription, and sink are declared in Terraform, but authenticated
  push delivery, Cloud Run deployment, and its private network connectivity are
  not fully provisioned by the current configuration.
License
MIT — use it, exte
