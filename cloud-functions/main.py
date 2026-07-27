import logging
from flask import Flask, request
from normalizer import normalize_event, NormalizationError
from enrichment import enrich_event
from detector import run_detections
from rule_loader import load_rules
from correlation import EventHistory, run_correlations
from opensearch_client import index_event
from alerter import send_slack_alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

RULES = load_rules()
if not RULES:
    logger.warning("No detection rules loaded -- detector will not fire on any event")

# Created once at process startup, same lifecycle as RULES. Mutated in
# place across requests -- see correlation.py's module docstring for
# why this is process-local, in-memory state (known Cloud Run
# limitation: doesn't survive multi-instance scaling or cold starts).
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

    index_event(enriched)
    for finding in hits:
        send_slack_alert(finding, enriched)

    for correlation_finding in correlated:
        # Indexing is safe as-is -- index_event() just serializes
        # whatever dict it's given, so a correlated finding's
        # different shape (no single "event", has
        # "contributing_findings" instead) works without changes.
        index_event(correlation_finding)

        # ASSUMPTION, NOT VERIFIED: send_slack_alert()'s real
        # implementation is unknown to me. Every call I've seen passes
        # (finding_dict, single_event_dict). A correlated finding has
        # no single source event, so I'm synthesizing one from what IS
        # available (actor + the contributing findings) as a
        # placeholder. This is the one part of Day 9 that needs your
        # alerter.py to confirm -- it may need a real fix, not just a
        # signature match, once you show me what the function actually
        # reads off `event`.
        synthetic_event = {
            "actor": correlation_finding["correlation_actor"],
            "action": f"correlation: {correlation_finding['rule_name']}",
            "contributing_findings": correlation_finding["contributing_findings"],
        }
        send_slack_alert(correlation_finding, synthetic_event)

    return "OK", 200


if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
