import logging
import requests
from config import SLACK_WEBHOOK_URL
logger = logging.getLogger(__name__)


def send_slack_alert(finding, normalized):
    """
    Send a formatted Slack alert for a detection or correlation hit.

    finding: a finding dict as produced by run_detections() --
        {"rule_name": ..., "mitre_technique": ..., "severity": ..., ...}
        (BUGFIX: this previously read rule["name"] / rule["mitre"],
        which matched the pre-Day-1-refactor hardcoded rule dict shape,
        not the finding shape run_detections() has produced since.
        Every call was throwing KeyError before ever reaching the
        network request -- confirmed by reproducing the crash before
        this fix.)

    Same message layout, fixed red attachment color, 5s timeout,
    swallow-and-log-on-failure behavior as before -- only the field
    names read off `finding` changed to match reality.
    """
    message = {
        "text": ":rotating_light: *DETECTION ALERT*",
        "attachments": [
            {
                "color": "#ff0000",
                "fields": [
                    {"title": "Rule", "value": finding["rule_name"], "short": True},
                    {"title": "Severity", "value": finding["severity"], "short": True},
                    {"title": "MITRE ATT&CK", "value": finding["mitre_technique"], "short": True},
                    {"title": "Actor", "value": normalized.get("actor", "unknown"), "short": True},
                    {"title": "Action", "value": normalized.get("action", "unknown"), "short": False},
                    {"title": "Resource", "value": normalized.get("resource", "unknown"), "short": False},
                    {"title": "Source IP", "value": normalized.get("source_ip", "unknown"), "short": True},
                    {"title": "Timestamp", "value": normalized.get("timestamp", "unknown"), "short": True}
                ]
            }
        ]
    }
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=message, timeout=5)
        logger.info(f"Slack response: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"Slack error: {e}")
