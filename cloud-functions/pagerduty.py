import logging
import requests
from config import PAGERDUTY_ROUTING_KEY, PAGERDUTY_EVENTS_URL

logger = logging.getLogger(__name__)

# Map this project's severity vocabulary onto PagerDuty Events API v2's
# fixed four-level severity enum.
SEVERITY_MAP = {
    "LOW": "info",
    "MEDIUM": "warning",
    "HIGH": "error",
    "CRITICAL": "critical",
}


def send_pagerduty_alert(finding, normalized):
    """
    Trigger a PagerDuty incident via the Events API v2.

    Graceful degradation: if PAGERDUTY_ROUTING_KEY isn't configured,
    this logs a warning and returns WITHOUT attempting the request --
    an unset integration key is a valid, expected deployment state
    (not every environment running this project has a real PagerDuty
    account), not an error condition to raise on.

    Network/API failures during the actual request are caught and
    logged the same way opensearch_client.py and alerter.py already
    handle their own failures: never raises, never blocks the rest of
    the pipeline.
    """
    if not PAGERDUTY_ROUTING_KEY:
        logger.warning(
            f"PagerDuty routing key not configured -- skipping page for "
            f"'{finding.get('rule_name')}' (would have paged at severity "
            f"{finding.get('severity')})"
        )
        return

    severity = finding.get("severity", "LOW")
    pd_severity = SEVERITY_MAP.get(severity, "warning")

    payload = {
        "routing_key": PAGERDUTY_ROUTING_KEY,
        "event_action": "trigger",
        "payload": {
            "summary": f"{finding.get('rule_name', 'Unknown rule')} ({severity})",
            "source": normalized.get("actor", "unknown"),
            "severity": pd_severity,
            "custom_details": {
                "mitre_technique": finding.get("mitre_technique"),
                "action": normalized.get("action"),
                "resource": normalized.get("resource"),
                "source_ip": normalized.get("source_ip"),
                "timestamp": normalized.get("timestamp"),
            },
        },
    }

    try:
        response = requests.post(PAGERDUTY_EVENTS_URL, json=payload, timeout=5)
        logger.info(f"PagerDuty response: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"PagerDuty error: {e}")
