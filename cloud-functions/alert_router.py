"""
Alert router.

Decides which downstream systems a finding gets sent to, based on
severity. Replaces main.py calling send_slack_alert() directly --
now main.py calls route_alert() once per finding (detection or
correlation), and this module decides Slack / PagerDuty / neither.

OpenSearch indexing is deliberately NOT decided here: the enriched
event is indexed once per request in main.py regardless of whether
any rule fired (so "every severity, including LOW, ends up in
OpenSearch" is already true by construction), and correlation
findings are indexed as their own documents at the point they're
produced. Routing findings to Slack/PagerDuty is a fundamentally
per-finding decision; indexing the underlying event is not, so
keeping them separate avoids conflating two different concerns.

Pure-ish module: it calls out to alerter.py and pagerduty.py (both of
which do real network I/O), but has no Flask/Pub/Sub knowledge itself
and makes no decision based on anything except finding["severity"].
"""
import logging
from alerter import send_slack_alert
from pagerduty import send_pagerduty_alert

logger = logging.getLogger(__name__)

# Severity -> which channels fire, beyond OpenSearch (which is
# unconditional -- see module docstring).
ROUTING_TABLE = {
    "LOW":      {"slack": False, "pagerduty": False},
    "MEDIUM":   {"slack": True,  "pagerduty": False},
    "HIGH":     {"slack": True,  "pagerduty": True},
    "CRITICAL": {"slack": True,  "pagerduty": True},
}

# Fallback for a severity value that isn't one of the four expected
# buckets (e.g. a future rule with a typo'd severity, or a correlation
# rule someone adds without checking against this table). Fail toward
# visibility, not silence: notify Slack so a human sees it, don't page
# for something whose real severity is unknown.
DEFAULT_ROUTING = {"slack": True, "pagerduty": False}


def route_alert(finding, normalized):
    """
    finding: a finding dict (from run_detections() or
        run_correlations()) -- must have "severity" and "rule_name".
    normalized: the event context to attach to the alert message --
        the enriched event for a detection finding, or a synthesized
        event for a correlation finding (see main.py).
    """
    severity = finding.get("severity")
    routing = ROUTING_TABLE.get(severity)

    if routing is None:
        logger.warning(
            f"Finding '{finding.get('rule_name')}' has unrecognized "
            f"severity '{severity}' -- using default routing (Slack only)"
        )
        routing = DEFAULT_ROUTING

    if routing["slack"]:
        send_slack_alert(finding, normalized)

    if routing["pagerduty"]:
        send_pagerduty_alert(finding, normalized)
