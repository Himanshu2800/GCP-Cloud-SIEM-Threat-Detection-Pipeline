
import logging

from alerter import send_slack_alert

from pagerduty import send_pagerduty_alert

logger = logging.getLogger(__name__)

ROUTING_TABLE = {

"LOW": {"slack": False, "pagerduty": False},

"MEDIUM": {"slack": True, "pagerduty": False},

"HIGH": {"slack": True, "pagerduty": True},

"CRITICAL": {"slack": True, "pagerduty": True},

}

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
