import ipaddress
import logging
from copy import deepcopy

logger = logging.getLogger(__name__)

RESOURCE_TYPE_BY_LOG_SOURCE = {
    "compute.googleapis.com": "GCE Instance",
    "storage.googleapis.com": "Cloud Storage Bucket",
    "iam.googleapis.com": "IAM Service Account",
    "cloudresourcemanager.googleapis.com": "IAM Policy",
}


def classify_resource_type(normalized: dict) -> str:
    log_source = normalized.get("log_source", "")
    return RESOURCE_TYPE_BY_LOG_SOURCE.get(log_source, "Unknown")

EVENT_CATEGORY_PATTERNS = [

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
    return normalized.get("action", "Unknown action")
def calculate_risk_score(event_category: str, ip_classification: str) -> str:
    if event_category == "Deletion" and ip_classification == "public":
        return "CRITICAL"
    if event_category == "Permission Change" and ip_classification == "public":
        return "CRITICAL"
    if event_category in ("Deletion", "Permission Change"):

        return "HIGH"
    if event_category == "Credential Creation":

        return "HIGH"
    if event_category == "Read/List":
        return "LOW"
    return "MEDIUM"
def _mask_ip(ip):
    if not ip or ip == "unknown":
        return ip
    parts = str(ip).split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3] + ["xxx"])
    return ip
def enrich_event(normalized: dict) -> dict:
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
