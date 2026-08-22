"""
Alert router decides who gets pinged (Slack, PagerDuty, or nobody)
based on how bad a finding is. OpenSearch indexing is handled
elsewhere and always happens, so it's not this module's problem.
"""
import logging
from alerter import send_slack_alert
from pagerduty import send_pagerduty_alert

logger = logging.getLogger(__name__)

# what fires for each severity level
ROUTING_TABLE = {
    "LOW":      {"slack": False, "pagerduty": False},
    "MEDIUM":   {"slack": True,  "pagerduty": False},
    "HIGH":     {"slack": True,  "pagerduty": True},
    "CRITICAL": {"slack": True,  "pagerduty": True},
}

# unknown severity? ping slack so a human notices, but don't page blind
DEFAULT_ROUTING = {"slack": True, "pagerduty": False}


def route_alert(finding, normalized):
    """Send a finding to Slack and/or PagerDuty based on severity."""
    severity = finding.get("severity")
    routing = ROUTING_TABLE.get(severity)

    if routing is None:
        logger.warning(
            f"Unknown severity '{severity}' for '{finding.get('rule_name')}', "
            "defaulting to Slack only routing"
        )
        routing = DEFAULT_ROUTING

    if routing["slack"]:
        send_slack_alert(finding, normalized)

    if routing["pagerduty"]:
        send_pagerduty_alert(finding, normalized)
