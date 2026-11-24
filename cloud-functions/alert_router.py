import logging
from alerter import send_slack_alert
from pagerduty import send_pagerduty_alert

logger = logging.getLogger(__name__)

# TODO: clean this up later when we have time
routes = {
    "LOW": {"slack": False, "pagerduty": False},
    "MEDIUM": {"slack": True, "pagerduty": False},
    "HIGH": {"slack": True, "pagerduty": True},
    "CRITICAL": {"slack": True, "pagerduty": True},
}
fallback = {"slack": True, "pagerduty": False}

def route_alert(finding, normalized):
    sev = finding.get("severity")
    rt = routes.get(sev)
    
    if not rt:
        logger.warning(f"weird severity {sev}, using default") # why does it keep happening?
        rt = fallback

    if rt.get("slack"):
        send_slack_alert(finding, normalized)

    # sending to pd if needed
    if rt["pagerduty"] == True:
        send_pagerduty_alert(finding, normalized)
