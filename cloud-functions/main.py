import logging
from flask import Flask, request
from normalizer import normalize_event, NormalizationError
from enrichment import enrich_event
from detector import run_detections
from rule_loader import load_rules
from opensearch_client import index_event
from alerter import send_slack_alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

RULES = load_rules()
if not RULES:
    logger.warning("No detection rules loaded -- detector will not fire on any event")


@app.route("/", methods=["POST"])
def handle_pubsub_push():
    envelope = request.get_json(silent=True)
    try:
        normalized = normalize_event(envelope)
    except NormalizationError as e:
        logger.error(f"Normalization failed: {e}")
        return f"Bad Request: {e}", 400

    # Enrichment happens right after normalization, before anything
    # else touches the event, so detection, indexing, and alerting
    # all see the same enriched document rather than three different
    # partially-enriched views of it.
    enriched = enrich_event(normalized)

    hits = run_detections(enriched, RULES)
    index_event(enriched)
    for rule in hits:
        send_slack_alert(rule, enriched)

    return "OK", 200


if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
