import logging
import requests
from config import SLACK_WEBHOOK_URL
logger = logging.getLogger(__name__)

def send_slack_alert(finding, normalized):

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
        logger.info(f"Slack response: {response.status_code}, {response.text}")
    except Exception as e:
        logger.error(f"Slack error: {e}")
