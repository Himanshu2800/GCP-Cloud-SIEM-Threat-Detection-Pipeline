import logging
import requests
from config import PAGERDUTY_ROUTING_KEY, PAGERDUTY_EVENTS_URL

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "LOW": "info",
    "MEDIUM": "warning",
    "HIGH": "error",
    "CRITICAL": "critical",
}


def _mask_actor(actor):
    if not actor or actor == "unknown":
        return actor
    if "@" in actor:
        name, domain = actor.split("@", 1)
        visible = name[:2]
        return f"{visible}{'*' * max(len(name) - 2, 3)}@{domain}"
    visible = actor[:2]
    return f"{visible}{'*' * max(len(actor) - 2, 3)}"


def _mask_ip(ip):
    if not ip or ip == "unknown":
        return ip
    parts = str(ip).split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3] + ["xxx"])
    return ip


def send_pagerduty_alert(finding, normalized):
    if not PAGERDUTY_ROUTING_KEY:
        logger.warning(
            f"PagerDuty routing key not configured, skipping page for "
            f"'{finding.get('rule_name')}' (would have paged at severity "
            f"{finding.get('severity')})"
        )
        return

    severity = finding.get("severity", "LOW")
    pd_severity = SEVERITY_MAP.get(severity, "warning")

    masked_actor = _mask_actor(normalized.get("actor", "unknown"))
    masked_ip = _mask_ip(normalized.get("source_ip"))

    payload = {
        "routing_key": PAGERDUTY_ROUTING_KEY,
        "event_action": "trigger",
        "payload": {
            "summary": f"{finding.get('rule_name', 'Unknown rule')} ({severity})",
            "source": masked_actor,
            "severity": pd_severity,
            "custom_details": {
                "mitre_technique": finding.get("mitre_technique"),
                "action": normalized.get("action"),
                "resource": normalized.get("resource"),
                "source_ip": masked_ip,
                "timestamp": normalized.get("timestamp"),
            },
        },
    }

    try:
        response = requests.post(PAGERDUTY_EVENTS_URL, json=payload, timeout=5)
        logger.info(f"PagerDuty response: {response.status_code}, {response.text}")
    except Exception as e:
        logger.error(f"PagerDuty error: {e}")
