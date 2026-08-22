import json
import logging
from datetime import datetime, timezone

import requests
from config import OPENSEARCH_URL, OPENSEARCH_USER, OPENSEARCH_PASS, INDEX_NAME

logger = logging.getLogger(__name__)

VALID_DOC_TYPES = {"raw_event", "detection", "correlation"}


def _build_document(payload, doc_type):
    """
    Wrap a payload dict into this project's consistent OpenSearch
    document schema, regardless of which pipeline stage produced it.

    Every indexed document carries, no matter its doc_type:

      doc_type: "raw_event", "detection", or "correlation". Lets an
      analyst (or a Grafana filter) distinguish a plain audit log
      event from a rule match from a multi event correlation without
      inspecting which fields happen to be present.

      ingested_at: when this document was written to OpenSearch,
      distinct from the event's own "timestamp" (when the activity
      actually happened in GCP). Conflating the two was a real gap
      in the original schema, a pipeline delay or replay would
      otherwise be invisible.

      severity: normalized to this project's LOW/MEDIUM/HIGH/
      CRITICAL vocabulary for every doc_type, so one Grafana filter
      works across raw events, detections, and correlations alike.
      For a raw event this is the enrichment risk_score bucket,
      deliberately not the source GCP audit log's own "severity"
      field, which uses an unrelated vocabulary (NOTICE, WARNING,
      etc). That field is preserved as log_severity instead of being
      silently overwritten or lost.

      mitre_technique: a real technique ID for detections and
      correlations, explicitly None (not omitted) for raw events, so
      the field has a consistent type across every document in the
      index rather than sometimes existing, sometimes not.

      timestamp: backfilled at the top level if the payload doesn't
      already have one, from the nested finding["event"] for a
      detection, or from the last contributing finding for a
      correlation, so every document type sorts correctly on a time
      axis in OpenSearch/Grafana.
    """
    if doc_type not in VALID_DOC_TYPES:
        logger.error(
            f"Unknown doc_type '{doc_type}', must be one of {VALID_DOC_TYPES}. "
            f"Skipping index, never crash the pipeline over an indexing bug."
        )
        return None

    document = dict(payload)  # shallow copy, never mutate the caller's dict
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
    """
    Shared low level POST. Same behavior as the original index_event():
    basic auth, TLS verification disabled, never raises, logs and
    swallows any failure so a downstream OpenSearch outage never
    breaks detection or alerting.

    TODO (reliability commit, carried over from Day 1, still deferred):
    doesn't call response.raise_for_status(), so a 4xx/5xx response is
    logged at INFO and treated as success.
    """
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
    """
    Index any pipeline document, raw event, detection finding, or
    correlation finding, under the project's consistent schema.

    This is now the one entry point for all OpenSearch writes. See
    main.py: it calls this once per raw event, once per detection
    finding, and once per correlation finding. (Previously, detection
    findings were never indexed at all, see the Day 11 schema audit
    notes for why that was a real gap, not a style choice.)
    """
    document = _build_document(payload, doc_type)
    if document is None:
        return
    _post_document(document)


def index_event(normalized):
    """
    Backward compatible wrapper for any external code still calling
    the old signature: indexes a raw normalized/enriched event.
    Equivalent to index_document(normalized, doc_type="raw_event").
    """
    index_document(normalized, doc_type="raw_event")
