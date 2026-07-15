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
                "event": normalized,
            }
            hits.append(finding)
    return hits
