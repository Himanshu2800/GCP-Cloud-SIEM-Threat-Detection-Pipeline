import json
import logging
import requests

from config import OPENSEARCH_URL, OPENSEARCH_USER, OPENSEARCH_PASS, INDEX_NAME

logger = logging.getLogger(__name__)


def index_event(normalized):
    """
    Index a normalized event document into OpenSearch.
    Same behaviour as the original main.py: POST to
    {OPENSEARCH_URL}/{INDEX_NAME}/_doc with basic auth,
    TLS verification disabled, never raises on failure.

    TODO (reliability commit, not Day 1): this only catches network-level
    exceptions (connection errors, timeouts, TLS failures). A 4xx/5xx
    HTTP response from OpenSearch (e.g. 401 auth rejected, 500 cluster
    error) is NOT an exception to `requests` — it's a well-formed
    response — so it's currently logged at INFO and treated as success.
    Add `response.raise_for_status()` after the request in a follow-up
    commit to convert HTTP error responses into caught exceptions.
    Deferred here because it changes failure-handling behaviour, and
    today's rule is behaviour-preserving refactor only.
    """
    try:
        response = requests.post(
            f"{OPENSEARCH_URL}/{INDEX_NAME}/_doc",
            auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
            headers={"Content-Type": "application/json"},
            data=json.dumps(normalized),
            verify=False
        )
        logger.info(f"OpenSearch response: {response.status_code}")
    except Exception as e:
        logger.error(f"OpenSearch error: {e}")
