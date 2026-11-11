import base64
import json
import logging
logger = logging.getLogger(__name__)
class NormalizationError(Exception):
    pass
def decode_pubsub_envelope(envelope: dict) -> dict:
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


def is_vpc_flow_log(log: dict) -> bool:
    """VPC Flow Logs carry jsonPayload.connection, not protoPayload."""
    if str(log.get("logName", "")).endswith("vpc_flows"):
        return True
    payload = log.get("jsonPayload")
    return isinstance(payload, dict) and "connection" in payload


def _to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_vpc_flow_log(log: dict) -> dict:
    payload = log.get("jsonPayload") or {}
    conn = payload.get("connection") or {}
    src_vm = (payload.get("src_instance") or {}).get("vm_name")
    dest_vm = (payload.get("dest_instance") or {}).get("vm_name")
    src_ip = conn.get("src_ip")
    dest_ip = conn.get("dest_ip")
    return {
        "timestamp": log.get("timestamp"),
        # Flow logs have no principal, so the source VM (or IP) is the actor.
        "actor": src_vm or src_ip or "unknown",
        "action": "vpc_flow",
        "resource": dest_vm or dest_ip or "unknown",
        "source_ip": src_ip or "unknown",
        "log_source": "compute.googleapis.com",
        "severity": log.get("severity", "unknown"),
        "dest_ip": dest_ip or "unknown",
        "dest_port": _to_int(conn.get("dest_port"), None),
        "protocol": conn.get("protocol"),
        # GCP serialises bytes_sent as a string, so convert for numeric rules.
        "bytes_sent": _to_int(payload.get("bytes_sent")),
        "reporter": payload.get("reporter", "unknown"),
        "raw": log,
    }


def normalize_event(envelope: dict) -> dict:
    log = decode_pubsub_envelope(envelope)
    if is_vpc_flow_log(log):
        return normalize_vpc_flow_log(log)
    return normalize_gcp_log(log)
