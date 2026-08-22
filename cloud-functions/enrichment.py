"""
Enrichment module.

Takes a normalized event (normalize_event()'s output) and returns a
new dict augmented with derived context: resource type, event
category, IP classification, a human readable action description,
and a deterministic risk score bucket.

Sits between normalization and everything else in the pipeline:

    normalize_event() then enrich_event() then run_detections(),
    index_event(), send_slack_alert()

Deliberately independent of Flask, GCP, Pub/Sub, OpenSearch, same as
detector.py, it's a pure function of a dict, testable the same way
run_detections() is.

Every classifier here is table driven and deterministic on purpose,
no weighted scoring, no ML. Each output value should be explainable
by pointing at one line of code, that matters more for a portfolio
project than sophistication, and it keeps this easy to extend without
risking silent drift.
"""
import ipaddress
import logging
from copy import deepcopy

logger = logging.getLogger(__name__)

# resource_type: derived from log_source (the GCP API service name),
# since that's a reliable field normalizer.py already extracts as
# proto.get("serviceName").
RESOURCE_TYPE_BY_LOG_SOURCE = {
    "compute.googleapis.com": "GCE Instance",
    "storage.googleapis.com": "Cloud Storage Bucket",
    "iam.googleapis.com": "IAM Service Account",
    "cloudresourcemanager.googleapis.com": "IAM Policy",
}


def classify_resource_type(normalized: dict) -> str:
    log_source = normalized.get("log_source", "")
    return RESOURCE_TYPE_BY_LOG_SOURCE.get(log_source, "Unknown")


# event_category: pattern matched against `action`, same contains
# style matching detector.py already uses, keeps the mental model
# consistent across the codebase rather than introducing a second way
# of matching actions.
EVENT_CATEGORY_PATTERNS = [
    # (substring to match in action, lowercased, category)
    ("delete", "Deletion"),
    ("setiampolicy", "Permission Change"),
    ("setiampermissions", "Permission Change"),
    ("createserviceaccountkey", "Credential Creation"),
    ("list", "Read/List"),
    ("get", "Read/List"),
]


def classify_event_category(normalized: dict) -> str:
    action = str(normalized.get("action", "")).lower()
    for pattern, category in EVENT_CATEGORY_PATTERNS:
        if pattern in action:
            return category
    return "Other"


# ip_classification: uses the ipaddress module against source_ip.
# "unknown" covers both a missing field and a value that isn't a
# parseable IP at all (normalizer.py defaults missing callerIp to the
# string "unknown", not a real address).
#
# Explicit internal network ranges rather than relying on the stdlib
# ip_address.is_private property. is_private is broader than "actually
# on our internal network", it also flags RFC 5737 documentation and
# test ranges (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24) as
# private, since they're non routable on the public internet. Those
# exact ranges are the ones used in this project's test fixtures to
# represent an external attacker IP (correct practice, never commit
# real public IPs to test data), so relying on is_private would have
# silently misclassified every "external attacker" fixture as
# internal. Explicit ranges make "private" mean what it needs to mean
# here: inside our network, full stop.
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
]


def classify_ip(normalized: dict) -> str:
    source_ip = normalized.get("source_ip")
    if not source_ip or source_ip == "unknown":
        return "unknown"
    try:
