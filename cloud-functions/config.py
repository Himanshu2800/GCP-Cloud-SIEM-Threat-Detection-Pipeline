import os
OPENSEARCH_URL = "https://10.0.0.7:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = os.environ.get("OPENSEARCH_PASS")
INDEX_NAME = "gcp-audit-logs"
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

# PagerDuty Events API v2 -- set PAGERDUTY_ROUTING_KEY via environment
# (same pattern as OPENSEARCH_PASS / SLACK_WEBHOOK_URL above). Leaving
# this unset is a valid, expected state (see pagerduty.py) -- not
# every deployment of this project needs a real PagerDuty account.
PAGERDUTY_ROUTING_KEY = os.environ.get("PAGERDUTY_ROUTING_KEY")
PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
