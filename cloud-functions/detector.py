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

# Operators supported in v1. Extend this set (regex, numeric comparisons,
# startswith, etc.) in a future engine revision — not today's scope.
SUPPORTED_OPERATORS = {"contains", "equals", "not_contains"}


def evaluate_condition(condition, normalized):
    """
    Evaluate a single condition against a normalized event.

    condition: {"field": str, "operator": str, "value": str}
    normalized: the normalized event dict

    Returns True/False only. Knows nothing about rules, MITRE,
    severity, or AND/OR combination — that's run_detections()'s job.

    Fails closed: any ambiguity (missing field, malformed condition,
    unsupported operator) resolves to False rather than raising or
    silently matching.
    """
    field = condition.get("field")
    operator = condition.get("operator")
    value = condition.get("value")

    if field is None or operator is None or value is None:
        logger.warning(f"Malformed condition {condition} — treating as False")
        return False

    field_value = normalized.get(field)
    if field_value is None:
        # Field missing from the event — fail closed.
        return False

    if operator not in SUPPORTED_OPERATORS:
        logger.warning(
            f"Unsupported operator '{operator}' in condition {condition} "
            f"— treating condition as False"
        )
        return False

    # Normalize types for comparison (same case-insensitive string
    # comparison behavior as the original inline "contains" logic).
    field_value = str(field_value).lower()
    value = str(value).lower()

    if operator == "contains":
        return value in field_value
    elif operator == "equals":
        return field_value == value
    elif operator == "not_contains":
        return value not in field_value


def run_detections(normalized):
    """
    Evaluate a normalized event against DETECTION_RULES.

    Each rule defines one or more conditions, combined via the rule's
    condition_logic (AND/OR). Per-condition evaluation is delegated to
    evaluate_condition(); this function is only responsible for rule
    iteration, AND/OR combination, and finding assembly.

    Returns the list of finding dicts that fired, so main.py can decide
    what to do with them (originally this called send_slack_alert
    inline — that side effect now belongs to alerter.py).
    """
    findings = []
    for rule in DETECTION_RULES:
        condition_results = [
            evaluate_condition(condition, normalized)
            for condition in rule["conditions"]
        ]

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
            findings.append(finding)
    return findings
