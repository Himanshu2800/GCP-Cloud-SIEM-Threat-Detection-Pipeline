import logging
from copy import deepcopy

logger = logging.getLogger(__name__)

# Detection rules mapped to MITRE ATT&CK
# (unchanged from original main.py)
DETECTION_RULES = [
    {
        "name": "GCP VM Instance Deleted",
        "severity": "MEDIUM",
        "mitre": "T1485",
        "condition_logic": "AND",
        "conditions": [
            {
                "field": "action",
                "operator": "contains",
                "value": "compute.instances.delete"
            }
        ]
    },
    {
        "name": "GCP IAM Policy Modified",
        "severity": "HIGH",
        "mitre": "T1078",
        "condition_logic": "AND",
        "conditions": [
            {
                "field": "action",
                "operator": "contains",
                "value": "setIamPolicy"
            }
        ]
    },
    {
        "name": "GCP Firewall Rule Deleted",
        "severity": "HIGH",
        "mitre": "T1562.007",
        "condition_logic": "AND",
        "conditions": [
            {
                "field": "action",
                "operator": "contains",
                "value": "firewalls.delete"
            }
        ]
    },
    {
        "name": "GCP Service Account Key Created",
        "severity": "HIGH",
        "mitre": "T1098.001",
        "condition_logic": "AND",
        "conditions": [
            {
                "field": "action",
                "operator": "contains",
                "value": "CreateServiceAccountKey"
            }
        ]
    },
    {
        "name": "GCP Storage Bucket Permissions Modified",
        "severity": "HIGH",
        "mitre": "T1530",
        "condition_logic": "AND",
        "conditions": [
            {
                "field": "action",
                "operator": "contains",
                "value": "storage.setIamPermissions"
            }
        ]
    }
]


def run_detections(normalized):
    """
    Evaluate a normalized event against DETECTION_RULES.
    Each rule defines one or more conditions, combined via the rule's
    condition_logic (AND/OR). All conditions are evaluated inline here
    for now; this will be extracted into evaluate_condition() as a
    follow-up refactor to keep run_detections() focused on iteration
    and finding assembly rather than condition evaluation itself.
    Returns the list of finding dicts that fired, so main.py can decide
    what to do with them (originally this called send_slack_alert
    inline — that side effect now belongs to alerter.py).
    """
    hits = []
    for rule in DETECTION_RULES:
        condition_results = []
        for condition in rule["conditions"]:
            field_value = normalized.get(condition["field"], "")
            operator = condition["operator"]
            value = condition["value"]

            if operator == "contains":
                result = value.lower() in field_value.lower()
            else:
                logger.warning(
                    f"Unsupported operator '{operator}' in rule "
                    f"'{rule['name']}' — treating condition as False"
                )
                result = False

            condition_results.append(result)

        if rule["condition_logic"] == "AND":
            rule_matched = all(condition_results)
        elif rule["condition_logic"] == "OR":
            rule_matched = any(condition_results)
        else:
            logger.warning(
                f"Unsupported condition_logic '{rule['condition_logic']}' "
                f"in rule '{rule['name']}' — skipping rule"
            )
            rule_matched = False

        if rule_matched:
            logger.info(f"DETECTION HIT: {rule['name']} ({rule['mitre']})")
            finding = {
                "rule_name": rule["name"],
                "mitre_technique": rule["mitre"],
                "severity": rule["severity"],
                "event": deepcopy(normalized),
            }
            hits.append(finding)
    return hits
