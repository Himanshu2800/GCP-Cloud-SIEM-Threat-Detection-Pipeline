import os
OPENSEARCH_URL = "https://10.0.0.xxx:9200"
OPENSEARCH_USER = "ad***"
OPENSEARCH_PASS = os.environ.get("OPENSEARCH_PASS")
INDEX_NAME = "gcp-audit-logs"
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

PAGERDUTY_ROUTING_KEY = os.environ.get("PAGERDUTY_ROUTING_KEY")
PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
