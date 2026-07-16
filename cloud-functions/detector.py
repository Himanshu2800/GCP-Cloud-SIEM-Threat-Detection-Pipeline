import logging
from copy import deepcopy

logger = logging.getLogger(__name__)

# Detection rules mapped to MITRE ATT&CK
# (unchanged from original main.py)
DETECTION_RULES = [
    {
        "name": "GCP VM Instance Deleted",
        "field": "action",
        "contains": "compute.instances.delete",
        "severity": "MEDIUM",
        "mitre": "T1485"
    },
    {
        "name": "GCP IAM Policy Modified",
        "field": "action",
        "contains": "setIamPolicy",
        "severity": "HIGH",
        "mitre": "T1078"
    },
    {
        "name": "GCP Firewall Rule Deleted",
        "field": "action",
        "contains": "firewalls.delete",
        "severity": "HIGH",
        "mitre": "T1562.007"
    },
    {
        "name": "GCP Service Account Key Created",
        "field": "action",
        "contains": "CreateServiceAccountKey",
        "severity": "HIGH",
        "mitre": "T1098.001"
    },
    {
        "name": "GCP Storage Bucket Permissions Modified",
        "field": "action",
        "contains": "storage.setIamPermissions",
        "severity": "HIGH",
        "mitre": "T1530"
    }
]


def run_detections(normalized):
    """
    Evaluate a normalized event against DETECTION_RULES.
    Same substring-match behaviour as the original main.py:
    case-insensitive 'contains' check on a single field.
    Returns the list of finding dicts that fired, so main.py can decide
    what to do with them (originally this called send_slack_alert
    inline — that side effect now belongs to alerter.py).
    """
    hits = []
    for rule in DETECTION_RULES:
        field_value = normalized.get(rule["field"], "")
        if rule["contains"].lower() in field_value.lower():
            logger.info(f"DETECTION HIT: {rule['name']} ({rule['mitre']})")
            finding = {
                "rule_name": rule["name"],
                "mitre_technique": rule["mitre"],
                "severity": rule["severity"],
                "event": deepcopy(normalized),
            }
            hits.append(finding)
    return hits
