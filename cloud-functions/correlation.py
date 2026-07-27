"""
Correlation engine.

Detects multi-step attack patterns across findings produced by
run_detections(), using an in-memory, time-bounded history of recent
findings per actor.

Sits after detection in the pipeline:

    run_detections() -> run_correlations() -> index / alert

Pure module, same as normalizer.py / enrichment.py / detector.py: no
knowledge of Flask, Pub/Sub, or OpenSearch. Takes data in, returns
data out.

--- Design notes (the memory model IS the design here) ---

Retention: time-based, not count-based. HISTORY_RETENTION_SECONDS is
an outer bound -- every rule's own time_window_seconds must be <= it.
Records are pruned on every add(), so memory is bounded by traffic
rate x retention window rather than needing a separate cleanup job.

Relatedness key: same actor (principalEmail, from the normalized
event's "actor" field). This is the natural first question a SOC
analyst asks -- "what else did this identity do recently?" Same-
resource or same-source-IP correlation is a reasonable future
extension, not needed for the two scenarios implemented here.

Scope/persistence: process-local, in-memory, NOT shared across
instances or survived across restarts. This is a deliberate,
documented limitation for a portfolio project running on Cloud Run --
multiple instances or a cold start both lose this state. A production
version would back this with Redis or Firestore for shared state.
Worth stating plainly rather than glossing over -- it's a real
architectural tradeoff, and being able to explain it is worth more
than pretending it isn't there.
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
        "sequence": ["GCP IAM Policy Modified", "GCP Service Account Key Created"],
        "time_window_seconds": 900,  # 15 minutes
        "severity": "CRITICAL",
        "mitre_technique": "T1078 -> T1098.001",
        "description": (
            "IAM policy was modified, then a new service account key was "
            "created by the same actor shortly after -- consistent with "
            "privilege escalation followed by persistence via new credentials."
        ),
    },
    {
        "name": "Firewall Removal Before VM Destruction",
        "sequence": ["GCP Firewall Rule Deleted", "GCP VM Instance Deleted"],
        "time_window_seconds": 900,
        "severity": "CRITICAL",
        "mitre_technique": "T1562.007 -> T1485",
        "description": (
            "A firewall rule was deleted, then a VM instance was deleted by "
            "the same actor shortly after -- consistent with defense evasion "
            "followed by destructive activity."
        ),
    },
]


def _parse_timestamp(ts_str):
    """Parse a GCP audit log RFC3339 timestamp ('...Z' suffix) into an
    aware datetime. Returns None if missing/unparseable so callers can
    skip the record instead of crashing."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


class EventHistory:
    """Bounded in-memory record of recent findings, used to look back
    for correlation matches. See module docstring for the retention
    and relatedness design decisions."""

    def __init__(self, retention_seconds=HISTORY_RETENTION_SECONDS):
        self.retention_seconds = retention_seconds
        self._records = deque()

    def add(self, finding, event):
        timestamp = _parse_timestamp(event.get("timestamp"))
        if timestamp is None:
            logger.warning(
                f"Finding '{finding.get('rule_name')}' has an unparseable "
                f"or missing timestamp -- excluded from correlation history"
            )
            return
        record = {
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

    Walks the sequence backward from the second-to-last step, picking
    the MOST RECENT prior record for each earlier step -- the
    tightest-fitting match, which matters if the actor triggered the
    same rule_name more than once inside the window.

    Returns contributing records oldest-to-newest if matched, else None.
    """
    contributing = [latest_record]
    cursor_time = latest_record["timestamp"]

    for step_name in reversed(sequence[:-1]):
        candidates = [
            r for r in actor_records
            if r["rule_name"] == step_name and r["timestamp"] <= cursor_time
        ]
        if not candidates:
            return None
        match = max(candidates, key=lambda r: r["timestamp"])
        if (latest_record["timestamp"] - match["timestamp"]).total_seconds() > time_window_seconds:
            return None
        contributing.append(match)
        cursor_time = match["timestamp"]

    return list(reversed(contributing))


def _fingerprint(rule_name, contributing_records):
    """Identity for one specific correlation occurrence -- prevents
    emitting the same correlated finding twice for the same underlying
    evidence."""
    return (rule_name, tuple(sorted(
        (r["rule_name"], r["timestamp"].isoformat()) for r in contributing_records
    )))


def run_correlations(findings, event_history, seen_correlations=None):
    """
    findings: list of finding dicts from run_detections() for the
        CURRENT event.
    event_history: an EventHistory instance -- created once at process
        startup, passed in on every call, mutated in place (this call's
        findings get recorded into it here).
    seen_correlations: optional set for cross-call dedup. Pass the same
        set across calls (e.g. a module-level set in main.py) if you
        want correlations deduplicated over the process lifetime;
        otherwise a fresh set is used per call.

    Returns a list of correlated finding dicts shaped like a normal
    finding (rule_name / mitre_technique / severity) plus
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
            "rule_name": finding["rule_name"],
            "mitre_technique": finding["mitre_technique"],
            "severity": finding["severity"],
            "timestamp": latest_ts,
        }
        actor_records = event_history.get_by_actor(actor)

        for rule in CORRELATION_RULES:
            if finding["rule_name"] != rule["sequence"][-1]:
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
                f"CORRELATION HIT: {rule['name']} (actor={actor}, "
                f"{len(match)} contributing findings)"
            )
            correlated.append({
                "rule_name": rule["name"],
                "mitre_technique": rule["mitre_technique"],
                "severity": rule["severity"],
                "correlation_actor": actor,
                "contributing_findings": [
                    {
                        "rule_name": r["rule_name"],
                        "mitre_technique": r["mitre_technique"],
                        "severity": r["severity"],
                        "timestamp": r["timestamp"].isoformat(),
                    }
                    for r in match
                ],
            })

    return correlated
