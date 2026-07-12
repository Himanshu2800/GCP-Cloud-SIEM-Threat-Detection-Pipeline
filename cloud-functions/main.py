import logging

from flask import Flask, request

from normalizer import normalize_event, NormalizationError
from detector import run_detections
from opensearch_client import index_event
from alerter import send_slack_alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)


@app.route("/", methods=["POST"])
def handle_pubsub_push():
    envelope = request.get_json(silent=True)

    try:
        normalized = normalize_event(envelope)
    except NormalizationError as e:
        logger.error(f"Normalization failed: {e}")
        return f"Bad Request: {e}", 400

    hits = run_detections(normalized)

    index_event(normalized)

    for rule in hits:
        send_slack_alert(rule, normalized)

    return "OK", 200


if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
