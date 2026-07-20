import logging

from flask import Flask, request

from normalizer import normalize_event, NormalizationError
from detector import run_detections
from rule_loader import load_rules
from opensearch_client import index_event
from alerter import send_slack_alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Rules are loaded once at process startup, not per-request. run_detections()
# takes them as an argument (Option B) rather than loading them itself --
# see detector.py / rule_loader.py for the reasoning. If detections/
# is empty or every rule fails validation, RULES is simply [] and the
# service still starts and serves requests; it just won't fire any
# detections until a valid rule is dropped in and the service restarts.
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

    hits = run_detections(normalized, RULES)
    index_event(normalized)
    for rule in hits:
        send_slack_alert(rule, normalized)

    return "OK", 200


if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
