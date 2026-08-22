import os
OPENSEARCH_URL = "https://10.0.0.xxx:9200"
OPENSEARCH_USER = "ad***"
OPENSEARCH_PASS = os.environ.get("OPENSEARCH_PASS")
INDEX_NAME = "gcp-audit-logs"
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

# PagerDuty Events API v2, set PAGERDUTY_ROUTING_KEY via environment
# (same pattern as OPENSEARCH_PASS and SLACK_WEBHOOK_URL above). Leaving
# this unset is fine, not every deployment needs a real PagerDuty account.
PAGERDUTY_ROUTING_KEY = os.environ.get("PAGERDUTY_ROUTING_KEY")
PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
