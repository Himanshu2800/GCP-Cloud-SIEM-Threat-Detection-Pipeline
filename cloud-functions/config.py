import os

OPENSEARCH_URL = "https://10.0.0.7:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = os.environ.get("OPENSEARCH_PASS")
INDEX_NAME = "gcp-audit-logs"
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
