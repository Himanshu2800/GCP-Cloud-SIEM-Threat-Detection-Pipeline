
import logging
from collections import deque
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

HISTORY_RETENTION_SECONDS = 3600 

CORRELATION_RULES = [
    {
        "name": "Privilege Escalation via Key Creation",
        "sequence": ["GCP_IAM_POLICY_MODIFIED", "GCP_SERVICE_ACCOUNT_KEY_CREATED"],
        "time_window_seconds": 900, 
        "severity": "CRITICAL",
        "mitre_technique": "T1078 to T1098.001",
        "description": (
            "IAM policy was modified, then a new service account key was "
            "created by the same actor shortly after, consistent with "
            "privilege escalation followed by persistence via new credentials."
        ),
    },
    {
        "name": "Firewall Removal Before VM Destruction",
        "sequence": ["GCP_FIREWALL_RULE_DELETED", "GCP_VM_INSTANCE_DELETED"],
        "time_window_seconds": 900,
        "severity": "CRITICAL",
        "mitre_technique": "T1562.007 to T1485",
        "description": (
            "A firewall rule was deleted, then a VM instance was deleted by "
            "the same actor shortly after, consistent with defense evasion "
            "followed by destructive activity."
        ),
    },
]


def _mask_actor(actor):
    if not actor or actor == "unknown":
        return actor
    if "@" in actor:
        name, domain = actor.split("@", 1)
        visible = name[:2]
        return f"{visible}{'*' * max(len(name) - 2, 3)}@{domain}"
    visible = actor[:2]
    return f"{visible}{'*' * max(len(actor) - 2, 3)}"
def _parse_timestamp(ts_str):

    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None

class EventHistory:
    def __init__(self, retention_seconds=HISTORY_RETENTION_SECONDS):
        self.retention_seconds = retention_seconds
        self._records = deque()

    def add(self, finding, event):
        timestamp = _parse_timestamp(event.get("timestamp"))
        if timestamp is None:
            logger.warning(
                f"Finding '{finding.get('rule_id', finding.get('rule_name'))}' has an "
                f"unparseable or missing timestamp, excluded from correlation history"
            )
            return
        record = {
            "rule_id": finding["rule_id"],
            "rule_name": finding["rule_name"],
            "mitre_technique": finding["mitre_technique"],
            "severity": finding["severity"],
            "actor": event.get("actor", "unknown"),
            "timestamp": timestamp,
        }
        self._records.append(record)
        self._prune(reference_time=timestamp)

    def _prune(self, reference_time):
        cutoff = reference_time - timedelta(seconds=self.retention_seconds)
        while self._records and self._records[0]["timestamp"] < cutoff:
            self._records.popleft()

    def get_by_actor(self, actor):
        return [r for r in self._records if r["actor"] == actor]

    def __len__(self):
        return len(self._records)

def _find_sequence_match(actor_records, sequence, time_window_seconds, latest_record):

    contributing = [latest_record]
    cursor_time = latest_record["timestamp"]

    for step_id in reversed(sequence[:-1]):
        candidates = [
            r for r in actor_records
            if r["rule_id"] == step_id and r["timestamp"] <= cursor_time
        ]
        if not candidates:
            return None
        match = max(candidates, key=lambda r: r["timestamp"])
        if (latest_record["timestamp"] - match["timestamp"]).total_seconds() > time_window_seconds:
            return None
        contributing.append(match)
        cursor_time = match["timestamp"]

    return list(reversed(contributing))


def _fingerprint(correlation_name, contributing_records):

    return (correlation_name, tuple(sorted(
        (r["rule_id"], r["timestamp"].isoformat()) for r in contributing_records
    )))


def run_correlations(findings, event_history, seen_correlations=None):

    if seen_correlations is None:
        seen_correlations = set()

    correlated = []

    for finding in findings:
        event = finding.get("event", {})
        event_history.add(finding, event)

    for finding in findings:
        event = finding.get("event", {})
        actor = event.get("actor", "unknown")
        latest_ts = _parse_timestamp(event.get("timestamp"))
        if latest_ts is None:
            continue

        latest_record = {
            "rule_id": finding["rule_id"],
            "rule_name": finding["rule_name"],
            "mitre_technique": finding["mitre_technique"],
            "severity": finding["severity"],
            "timestamp": latest_ts,
        }
        actor_records = event_history.get_by_actor(actor)

        for rule in CORRELATION_RULES:
            if finding["rule_id"] != rule["sequence"][-1]:
                continue  # this finding isn't the trigger step for this rule

            match = _find_sequence_match(
                actor_records, rule["sequence"], rule["time_window_seconds"], latest_record
            )
            if match is None:
                continue

            fingerprint = _fingerprint(rule["name"], match)
            if fingerprint in seen_correlations:
                continue
            seen_correlations.add(fingerprint)

            logger.info(
                f"CORRELATION HIT: {rule['name']} (actor={_mask_actor(actor)}, "
                f"{len(match)} contributing findings)"
            )
            correlated.append({
                "rule_name": rule["name"],
                "mitre_technique": rule["mitre_technique"],
                "severity": rule["severity"],
                "correlation_actor": actor,
                "contributing_findings": [
                    {
                        "rule_id": r["rule_id"],
                        "rule_name": r["rule_name"],
                        "mitre_technique": r["mitre_technique"],
                        "severity": r["severity"],
                        "timestamp": r["timestamp"].isoformat(),
                    }
                    for r in match
                ],
            })

    return correlated
