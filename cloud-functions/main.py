import logging
from flask import Flask, request
from normalizer import normalize_event, NormalizationError
from enrichment import enrich_event
from detector import run_detections
from rule_loader import load_rules
from correlation import EventHistory, run_correlations
from opensearch_client import index_event
from alert_router import route_alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

RULES = load_rules()
if not RULES:
    logger.warning("No detection rules loaded -- detector will not fire on any event")

EVENT_HISTORY = EventHistory()
SEEN_CORRELATIONS = set()


@app.route("/", methods=["POST"])
def handle_pubsub_push():
    envelope = request.get_json(silent=True)
    try:
        normalized = normalize_event(envelope)
    except NormalizationError as e:
        logger.error(f"Normalization failed: {e}")
        return f"Bad Request: {e}", 400

    enriched = enrich_event(normalized)

    hits = run_detections(enriched, RULES)
    correlated = run_correlations(hits, EVENT_HISTORY, SEEN_CORRELATIONS)

    # The enriched event is always indexed, regardless of whether any
    # rule fired -- this is what makes "OpenSearch: always" true for
    # every severity, including LOW/no-detection events, without
    # needing a routing decision for it.
    index_event(enriched)

    for finding in hits:
        route_alert(finding, enriched)

    for correlation_finding in correlated:
        index_event(correlation_finding)
        synthetic_event = {
            "actor": correlation_finding["correlation_actor"],
            "action": f"correlation: {correlation_finding['rule_name']}",
            "contributing_findings": correlation_finding["contributing_findings"],
        }
        route_alert(correlation_finding, synthetic_event)

    return "OK", 200


if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
