import os
OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "https://localhost:9200")
OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.environ.get("OPENSEARCH_PASS")
INDEX_NAME = os.environ.get("INDEX_NAME", "gcp-audit-logs")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

PAGERDUTY_ROUTING_KEY = os.environ.get("PAGERDUTY_ROUTING_KEY")
PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
