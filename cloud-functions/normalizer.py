import base64
import json
import logging

logger = logging.getLogger(__name__)


class NormalizationError(Exception):
    """Raised when an incoming envelope or log can't be decoded or normalized."""
    pass


def decode_pubsub_envelope(envelope: dict) -> dict:
    """
    Decode the base64 encoded 'data' field of a Pub/Sub push envelope
    into the raw GCP Cloud Audit Log JSON.
    """
    if not envelope or "message" not in envelope:
        raise NormalizationError("missing 'message' in envelope")

    message = envelope["message"]
    if "data" not in message:
        raise NormalizationError("missing 'data' in envelope['message']")

    try:
        raw_bytes = base64.b64decode(message["data"])
        raw_data = raw_bytes.decode("utf-8")
        return json.loads(raw_data)
    except (base64.binascii.Error, UnicodeDecodeError) as e:
        raise NormalizationError(f"failed to decode base64/utf-8 payload: {e}")
    except json.JSONDecodeError as e:
        raise NormalizationError(f"failed to parse JSON log payload: {e}")


def normalize_gcp_log(log: dict) -> dict:
    """
    Extract relevant fields from a GCP Cloud Audit Log entry
    (protoPayload structure) and flatten into a normalized event.
    """
    proto = log.get("protoPayload", {})
    auth = proto.get("authenticationInfo", {})
    request_meta = proto.get("requestMetadata", {})

    normalized = {
        "timestamp": log.get("timestamp"),
        "actor": auth.get("principalEmail", "unknown"),
        "action": proto.get("methodName", "unknown"),
        "resource": proto.get("resourceName", "unknown"),
        "source_ip": request_meta.get("callerIp", "unknown"),
        "log_source": proto.get("serviceName", "unknown"),
        "severity": log.get("severity", "unknown"),
        "raw": log,
    }

    return normalized


def normalize_event(envelope: dict) -> dict:
    """
    Full pipeline entrypoint: envelope becomes decoded log becomes
    normalized event. Raises NormalizationError on any failure so
    main.py can return an appropriate HTTP status without crashing.
    """
    log = decode_pubsub_envelope(envelope)
    return normalize_gcp_log(log)
