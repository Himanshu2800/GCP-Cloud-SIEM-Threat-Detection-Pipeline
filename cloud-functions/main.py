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
        "name": "GCP Firewall Rule Deleted",
        "field": "action",
        "contains": "firewalls.delete",
        "severity": "HIGH",
        "mitre": "T1562.007"
    },
    {
        "name": "GCP Service Account Key Created",
        "field": "action",
        "contains": "CreateServiceAccountKey",
        "severity": "HIGH",
        "mitre": "T1098.001"
    },
    {
        "name": "GCP Storage Bucket Permissions Modified",
        "field": "action",
        "contains": "storage.setIamPermissions",
        "severity": "HIGH",
        "mitre": "T1530"
    }
]

def send_slack_alert(rule, normalized):
    message = {
        "text": ":rotating_light: *DETECTION ALERT*",
        "attachments": [
            {
                "color": "#ff0000",
                "fields": [
                    {"title": "Rule", "value": rule["name"], "short": True},
                    {"title": "Severity", "value": rule["severity"], "short": True},
                    {"title": "MITRE ATT&CK", "value": rule["mitre"], "short": True},
                    {"title": "Actor", "value": normalized.get("actor", "unknown"), "short": True},
                    {"title": "Action", "value": normalized.get("action", "unknown"), "short": False},
                    {"title": "Resource", "value": normalized.get("resource", "unknown"), "short": False},
                    {"title": "Source IP", "value": normalized.get("source_ip", "unknown"), "short": True},
                    {"title": "Timestamp", "value": normalized.get("timestamp", "unknown"), "short": True}
                ]
            }
        ]
    }
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=message, timeout=5)
        print(f"Slack response: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Slack error: {e}")

def run_detections(normalized):
    for rule in DETECTION_RULES:
        field_value = normalized.get(rule["field"], "")
        if rule["contains"].lower() in field_value.lower():
            print(f"DETECTION HIT: {rule['name']} ({rule['mitre']})")
            send_slack_alert(rule, normalized)

@app.route("/", methods=["POST"])
def normalize_log(request=None):
    envelope = request.get_json(silent=True)

    if not envelope or "message" not in envelope:
        return "Bad Request: missing message", 400

    # Decode base64 Pub/Sub message
    raw_data = base64.b64decode(envelope["message"]["data"]).decode("utf-8")
    log = json.loads(raw_data)

    # Extract fields
    proto = log.get("protoPayload", {})
    auth = proto.get("authenticationInfo", {})
    request_meta = proto.get("requestMetadata", {})

    # Build normalized event
    normalized = {
        "timestamp": log.get("timestamp"),
        "actor": auth.get("principalEmail", "unknown"),
        "action": proto.get("methodName", "unknown"),
        "resource": proto.get("resourceName", "unknown"),
        "source_ip": request_meta.get("callerIp", "unknown"),
        "log_source": proto.get("serviceName", "unknown"),
        "severity": log.get("severity", "unknown"),
        "raw": log
    }

    # Run detections
    run_detections(normalized)

    # Index to OpenSearch
    try:
        response = requests.post(
            f"{OPENSEARCH_URL}/{INDEX_NAME}/_doc",
            auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
            headers={"Content-Type": "application/json"},
            data=json.dumps(normalized),
            verify=False
        )
        print(f"OpenSearch response: {response.status_code}")
    except Exception as e:
        print(f"OpenSearch error: {e}")

    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
