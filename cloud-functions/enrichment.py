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
        addr = ipaddress.ip_address(source_ip)
    except ValueError:
        return "unknown"
    if any(addr in network for network in PRIVATE_NETWORKS):
        return "private"
    return "public"


# action_description: direct lookup keyed on the same substrings the
# detection rules already check, so a rule firing and its human
# description can never silently drift apart from each other.
ACTION_DESCRIPTIONS = [
    ("compute.instances.delete", "VM instance deleted"),
    ("setiampolicy", "IAM policy modified"),
    ("firewalls.delete", "Firewall rule deleted"),
    ("createserviceaccountkey", "Service account key created"),
    ("storage.setiampermissions", "Storage bucket permissions modified"),
    ("compute.instances.list", "VM instances listed"),
]


def humanize_action(normalized: dict) -> str:
    action = str(normalized.get("action", "")).lower()
    for pattern, description in ACTION_DESCRIPTIONS:
        if pattern in action:
            return description
    # Fallback: return the raw action rather than inventing a
    # description for something not yet mapped, an honest "we don't
    # have a human label for this yet" beats a guessed one.
    return normalized.get("action", "Unknown action")


# risk_score: computed last since it depends on event_category and
# ip_classification. Deterministic table, not a weighted formula,
# every bucket traces to one branch below.
def calculate_risk_score(event_category: str, ip_classification: str) -> str:
    if event_category == "Deletion" and ip_classification == "public":
        return "CRITICAL"
    if event_category == "Permission Change" and ip_classification == "public":
        return "CRITICAL"
    if event_category in ("Deletion", "Permission Change"):
        # private or unknown source IP, still meaningfully risky,
        # just not "external attacker" risky.
        return "HIGH"
    if event_category == "Credential Creation":
        # Key creation is inherently risky regardless of source IP,
        # a stolen internal service account can create keys too.
        return "HIGH"
    if event_category == "Read/List":
        return "LOW"
    return "MEDIUM"


def _mask_ip(ip):
    """Mask the last octet of an IPv4 address for logging, e.g. 10.0.0.42 becomes 10.0.0.xxx"""
    if not ip or ip == "unknown":
        return ip
    parts = str(ip).split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3] + ["xxx"])
    return ip


def enrich_event(normalized: dict) -> dict:
    """
    Return a new dict: the normalized event plus derived context
    fields. Does not mutate the input, same deepcopy then augment
    pattern run_detections() already uses for finding["event"].
    """
    enriched = deepcopy(normalized)

    resource_type = classify_resource_type(normalized)
    event_category = classify_event_category(normalized)
    ip_classification = classify_ip(normalized)
    action_description = humanize_action(normalized)
    risk_score = calculate_risk_score(event_category, ip_classification)

    enriched["resource_type"] = resource_type
    enriched["event_category"] = event_category
    enriched["ip_classification"] = ip_classification
    enriched["action_description"] = action_description
    enriched["risk_score"] = risk_score

    masked_ip = _mask_ip(normalized.get("source_ip"))
    logger.info(
        f"Enriched event: {resource_type}, {event_category}, "
        f"ip_class={ip_classification} ({masked_ip}), risk={risk_score}"
    )
    return enriched
