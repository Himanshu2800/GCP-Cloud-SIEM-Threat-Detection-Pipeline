import json
import logging
from datetime import datetime, timezone

import requests
from config import OPENSEARCH_URL, OPENSEARCH_USER, OPENSEARCH_PASS, INDEX_NAME

logger = logging.getLogger(__name__)

VALID_DOC_TYPES = {"raw_event", "detection", "correlation"}


def _build_document(payload, doc_type):

    if doc_type not in VALID_DOC_TYPES:
        logger.error(
            f"Unknown doc_type '{doc_type}', must be one of {VALID_DOC_TYPES}. "
            f"Skipping index, never crash the pipeline over an indexing bug."
        )
        return None

    document = dict(payload) 
    document["doc_type"] = doc_type
    document["ingested_at"] = datetime.now(timezone.utc).isoformat()
    document.setdefault("mitre_technique", None)

    if doc_type == "raw_event":
        if "severity" in document:
            document["log_severity"] = document.pop("severity")
        document["severity"] = document.get("risk_score", "UNKNOWN")

    elif doc_type == "detection":
        if "timestamp" not in document:
            nested_event = document.get("event", {})
            document["timestamp"] = nested_event.get("timestamp")

    elif doc_type == "correlation":
        if "timestamp" not in document:
            contributing = document.get("contributing_findings", [])
            if contributing:
                document["timestamp"] = contributing[-1].get("timestamp")

    return document


def _post_document(document):
    try:
        response = requests.post(
            f"{OPENSEARCH_URL}/{INDEX_NAME}/_doc",
            auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
            headers={"Content-Type": "application/json"},
            data=json.dumps(document),
            verify=False
        )
        logger.info(f"OpenSearch response: {response.status_code}")
    except Exception as e:
        logger.error(f"OpenSearch error: {e}")


def index_document(payload, doc_type):
    document = _build_document(payload, doc_type)
    if document is None:
        return
    _post_document(document)


def index_event(normalized):
    index_document(normalized, doc_type="raw_event")
