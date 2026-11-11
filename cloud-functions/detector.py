import logging
from copy import deepcopy

logger = logging.getLogger(__name__)

SUPPORTED_OPERATORS = {"contains", "equals", "not_contains", "greater_than"}


def _mask_actor(actor):
    """Mask an email or username for logging, keep only the first two characters visible."""
    if not actor or actor == "unknown":
        return actor
    if "@" in actor:
        name, domain = actor.split("@", 1)
        visible = name[:2]
        return f"{visible}{'*' * max(len(name) - 2, 3)}@{domain}"
    visible = actor[:2]
    return f"{visible}{'*' * max(len(actor) - 2, 3)}"


def evaluate_condition(condition, normalized):
    field = condition.get("field")
    operator = condition.get("operator")
    value = condition.get("value")

    if field is None or operator is None or value is None:
        logger.warning(f"Malformed condition {condition}, treating as False")
        return False

    field_value = normalized.get(field)
    if field_value is None:
        return False

    if operator not in SUPPORTED_OPERATORS:
        logger.warning(
            f"Unsupported operator '{operator}' in condition {condition}, "
            f"treating condition as False"
        )
        return False

    if operator == "greater_than":
        # Numeric comparison; a non-numeric field or value never matches.
        try:
            return float(field_value) > float(value)
        except (TypeError, ValueError):
            return False

    field_value = str(field_value).lower()
    value = str(value).lower()

    if operator == "contains":
        return value in field_value
    elif operator == "equals":
        return field_value == value
    elif operator == "not_contains":
        return value not in field_value


def run_detections(normalized, rules):
    findings = []
    for rule in rules:
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
                f"in rule '{rule['title']}', skipping rule"
            )
            rule_matched = False

        if rule_matched:
            mitre_technique = rule["mitre"]["technique"]
            masked_actor = _mask_actor(normalized.get("actor", "unknown"))
            logger.info(
                f"DETECTION HIT: {rule['rule_id']} ({mitre_technique}), actor={masked_actor}"
            )
            finding = {
                "rule_id": rule["rule_id"],
                "rule_name": rule["title"],
                "mitre_technique": mitre_technique,
                "severity": rule["severity"],
                "event": deepcopy(normalized),
            }
            findings.append(finding)
    return findings
