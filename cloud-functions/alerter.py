import logging
import requests

from config import SLACK_WEBHOOK_URL

logger = logging.getLogger(__name__)


def send_slack_alert(rule, normalized):
    """
    Send a formatted Slack alert for a detection hit.
    Same message shape and behaviour as the original main.py:
    fixed red attachment color, same field set/order, 5s timeout,
    swallow-and-log on failure (never raises).
    """
    message = {
        "text": ":rotating_light: *DETECTION ALERT*",
        "attachments": [
            {
                "color": "#ff0000",
                "fields": [
                    {"title": "Rule", "value": rule["name"], "short": True},
                    {"title": "Severity", "value": rule["severity"], "short": True},
                    {"title": "MITRE ATT&CK", "value": rule["mitre"], "short": True},
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
