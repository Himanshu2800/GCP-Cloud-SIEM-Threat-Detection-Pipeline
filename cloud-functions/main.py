import base64
import json
import os
import requests
from flask import Flask, request
from datetime import datetime

app = Flask(__name__)

OPENSEARCH_URL = "https://10.0.0.7:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = os.environ.get("OPENSEARCH_PASS")
INDEX_NAME = "gcp-audit-logs"
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

# Detection rules mapped to MITRE ATT&CK
DETECTION_RULES = [
    {
        "name": "GCP VM Instance Deleted",
        "field": "action",
        "contains": "compute.instances.delete",
        "severity": "MEDIUM",
        "mitre": "T1485"
    },
    {
        "name": "GCP IAM Policy Modified",
        "field": "action",
        "contains": "setIamPolicy",
        "severity": "HIGH",
        "mitre": "T1078"
    },
    {
        "name":
