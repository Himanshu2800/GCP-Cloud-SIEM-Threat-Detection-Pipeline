"""
Correlation engine.

Looks across findings from run_detections() to catch multi-step
attack patterns, using an in-memory, time-bounded history of recent
findings per actor.

Sits after detection in the pipeline:

    run_detections() then run_correlations() then index / alert

Pure module, same as normalizer.py, enrichment.py, detector.py: no
knowledge of Flask, Pub/Sub, or OpenSearch. Takes data in, returns
data out.

Design notes (the memory model is basically the whole design here):

Retention is time based, not count based. HISTORY_RETENTION_SECONDS
is an outer bound, every rule's own time_window_seconds must be less
than or equal to it. Records get pruned on every add(), so memory
stays bounded by traffic rate times retention window instead of
needing a separate cleanup job.

Relatedness is keyed on actor (principalEmail, from the normalized
event's "actor" field). That is the natural first question a SOC
analyst asks: what else did this identity do recently? Correlating
by same resource or same source IP is a reasonable future extension,
just not needed for the two scenarios implemented here.

Scope and persistence: process local, in memory, not shared across
instances and not survived across restarts. This is a deliberate,
documented limitation for a portfolio project running on Cloud Run,
multiple instances or a cold start both lose this state. A production
version would back this with Redis or Firestore for shared state.
Worth stating plainly rather than glossing over it, it is a real
architectural tradeoff, and being able to explain it is worth more
than pretending it is not there.
"""
import logging
from collections import deque
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Outer bound on how long a finding stays eligible for correlation,
# regardless of any individual rule's own (shorter) window.
HISTORY_RETENTION_SECONDS = 3600  # 1 hour

CORRELATION_RULES = [
    {
        "name": "Privilege Escalation via Key Creation",
        # References rule_id (stable), not the human readable rule title,
        # so renaming a rule's title in its YAML file can never silently
        # break this sequence match.
        "sequence": ["GCP_IAM_POLICY_MODIFIED", "GCP_SERVICE_ACCOUNT_KEY_CREATED"],
        "time_window_seconds": 900,  # 15 minutes
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
    """Mask an email or username for logging, keep only the first two characters visible."""
    if not actor or actor == "unknown":
        return actor
    if "@" in actor:
        name, domain = actor.split("@", 1)
        visible = name[:2]
        return f"{visible}{'*' * max(len(name) - 2, 3)}@{domain}"
    visible = actor[:2]
    return f"{visible}{'*' * max(len(actor) - 2, 3)}"


def _parse_timestamp(ts_str):
    """Parse a GCP audit log RFC3339 timestamp (the 'Z' suffix form) into an
    aware datetime. Returns None if missing or unparseable so callers can
    skip the record instead of crashing."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


class EventHistory:
    """Bounded in memory record of recent findings, used to look back
    for correlation matches. See module docstring for the retention
    and relatedness design decisions."""

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
    """
    Check whether `sequence` is satisfied ending at latest_record,
    within time_window_seconds of the earliest matching step.

    Walks the sequence backward from the second to last step, picking
    the most recent prior record for each earlier step, the tightest
    fitting match, which matters if the actor triggered the same
    rule_id more than once inside the window.

    Returns contributing records oldest to newest if matched, else None.
    """
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
    """Identity for one specific correlation occurrence, prevents
    emitting the same correlated finding twice for the same underlying
    evidence. Keyed on rule_id (stable) rather than rule_name (a
    display string that can be renamed without changing identity)."""
    return (correlation_name, tuple(sorted(
        (r["rule_id"], r["timestamp"].isoformat()) for r in contributing_records
    )))


def run_correlations(findings, event_history, seen_correlations=None):
    """
    findings: list of finding dicts from run_detections() for the
        current event.
    event_history: an EventHistory instance, created once at process
        startup, passed in on every call, mutated in place (this call's
        findings get recorded into it here).
    seen_correlations: optional set for cross call dedup. Pass the same
        set across calls (e.g. a module level set in main.py) if you
        want correlations deduplicated over the process lifetime,
        otherwise a fresh set is used per call.

    Returns a list of correlated finding dicts shaped like a normal
    finding (rule_name, mitre_technique, severity) plus
    contributing_findings, so the rest of the pipeline (alerter,
    OpenSearch indexing) needs minimal changes to handle them.
    """
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
