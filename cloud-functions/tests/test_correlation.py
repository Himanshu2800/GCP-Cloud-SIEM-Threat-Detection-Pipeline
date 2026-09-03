"""
Correlation engine regression test runner.

Independent of Flask, GCP, Pub/Sub, and OpenSearch -- imports only
correlation.py and exercises run_correlations() directly against
synthetic finding sequences (no detector.py or YAML rules involved;
correlation operates purely on already-produced findings).

Mirrors test_runner.py's style: no pytest dependency (requirements.txt
only lists flask, requests, urllib3, pyyaml), same PROJECT_ROOT-search
approach for locating the module under test, same pass/fail print
format and exit code convention.

Covers six scenarios end to end:
    1. Privilege-escalation correlation fires (IAM policy -> SA key,
       same actor, within window).
    2. Firewall/VM correlation fires (firewall delete -> VM delete,
       same actor, within window).
    3. Actor isolation: same two-step sequence but split across two
       different actors never correlates.
    4. Time-window enforcement: same actor, same sequence, but the
       second step lands outside the rule's time_window_seconds.
    5. Missing precursor: the trigger step fires with no matching
       first step anywhere in history.
    6. Dedup on replay: feeding the same trigger finding a second time
       must not emit a second correlated finding for evidence already
       seen.

Usage:
    python tests/test_correlation.py
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _locate_correlation_dir():
    """
    Find the directory containing correlation.py by searching the repo,
    rather than hardcoding a folder name that drifts every time the
    project gets reorganized. Same approach as test_runner.py's
    _locate_detector_dir() -- see that function for the reasoning.
    """
    if (PROJECT_ROOT / "correlation.py").exists():
        return PROJECT_ROOT

    matches = list(PROJECT_ROOT.rglob("correlation.py"))
    matches = [
        m for m in matches
        if "tests" not in m.parts
        and "venv" not in m.parts
        and "site-packages" not in m.parts
        and not any(part.startswith(".") for part in m.parts)
    ]

    if len(matches) == 1:
        return matches[0].parent
    if len(matches) == 0:
        print(f"FRAMEWORK ERROR: could not find correlation.py anywhere under {PROJECT_ROOT}")
        sys.exit(2)
    print("FRAMEWORK ERROR: found multiple correlation.py files, ambiguous which to import:")
    for m in matches:
        print(f"    {m}")
    sys.exit(2)


sys.path.insert(0, str(_locate_correlation_dir()))

from correlation import run_correlations, EventHistory  # noqa: E402


class TestFrameworkError(Exception):
    """Raised for problems with the test setup itself, not the
    correlation engine -- kept distinct from a failing test so the two
    failure modes are never confused in the output."""


def make_finding(rule_id, rule_name, mitre_technique, severity, actor, timestamp):
    """Build a finding dict shaped like what run_detections() produces
    plus the 'event' sub-dict correlation.py reads actor/timestamp
    from. timestamp is an RFC3339 string with a 'Z' suffix, same form
    GCP audit logs use."""
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "mitre_technique": mitre_technique,
        "severity": severity,
        "event": {"actor": actor, "timestamp": timestamp},
    }


IAM_POLICY_MODIFIED = ("GCP_IAM_POLICY_MODIFIED", "IAM Policy Modified", "T1078", "HIGH")
SA_KEY_CREATED = ("GCP_SERVICE_ACCOUNT_KEY_CREATED", "SA Key Created", "T1098.001", "HIGH")
FIREWALL_RULE_DELETED = ("GCP_FIREWALL_RULE_DELETED", "Firewall Rule Deleted", "T1562.007", "HIGH")
VM_INSTANCE_DELETED = ("GCP_VM_INSTANCE_DELETED", "VM Instance Deleted", "T1485", "MEDIUM")


def _finding_at(step, actor, timestamp):
    rule_id, rule_name, mitre, severity = step
    return make_finding(rule_id, rule_name, mitre, severity, actor, timestamp)


def test_privilege_escalation_correlation_fires():
    history = EventHistory()
    seen = set()

    first = _finding_at(IAM_POLICY_MODIFIED, "alice@example.com", "2026-01-01T00:00:00Z")
    second = _finding_at(SA_KEY_CREATED, "alice@example.com", "2026-01-01T00:05:00Z")

    initial = run_correlations([first], history, seen)
    result = run_correlations([second], history, seen)

    if initial != []:
        raise AssertionError(f"expected no correlation on first step alone, got {initial}")
    if len(result) != 1:
        raise AssertionError(f"expected exactly 1 correlation, got {len(result)}")
    if result[0]["rule_name"] != "Privilege Escalation via Key Creation":
        raise AssertionError(f"unexpected correlation name: {result[0]['rule_name']}")
    if result[0]["severity"] != "CRITICAL":
        raise AssertionError(f"expected CRITICAL severity, got {result[0]['severity']}")


def test_firewall_removal_before_vm_destruction_fires():
    history = EventHistory()
    seen = set()

    first = _finding_at(FIREWALL_RULE_DELETED, "bob@example.com", "2026-01-01T00:00:00Z")
    second = _finding_at(VM_INSTANCE_DELETED, "bob@example.com", "2026-01-01T00:10:00Z")

    run_correlations([first], history, seen)
    result = run_correlations([second], history, seen)

    if len(result) != 1:
        raise AssertionError(f"expected exactly 1 correlation, got {len(result)}")
    if result[0]["rule_name"] != "Firewall Removal Before VM Destruction":
        raise AssertionError(f"unexpected correlation name: {result[0]['rule_name']}")


def test_different_actors_do_not_correlate():
    history = EventHistory()
    seen = set()

    first = _finding_at(IAM_POLICY_MODIFIED, "alice@example.com", "2026-01-01T00:00:00Z")
    second = _finding_at(SA_KEY_CREATED, "mallory@example.com", "2026-01-01T00:05:00Z")

    run_correlations([first], history, seen)
    result = run_correlations([second], history, seen)

    if result != []:
        raise AssertionError(f"expected no correlation across different actors, got {result}")


def test_outside_time_window_does_not_correlate():
    history = EventHistory()
    seen = set()

    # Rule window is 900s (15 min); push the second step to 20 minutes
    # after the first so it falls just outside.
    first = _finding_at(IAM_POLICY_MODIFIED, "carol@example.com", "2026-01-01T00:00:00Z")
    second = _finding_at(SA_KEY_CREATED, "carol@example.com", "2026-01-01T00:20:00Z")

    run_correlations([first], history, seen)
    result = run_correlations([second], history, seen)

    if result != []:
        raise AssertionError(f"expected no correlation outside time window, got {result}")


def test_missing_precursor_does_not_correlate():
    history = EventHistory()
    seen = set()

    # SA key creation fires with no preceding IAM policy modification
    # anywhere in this actor's history.
    only_step = _finding_at(SA_KEY_CREATED, "dave@example.com", "2026-01-01T00:00:00Z")

    result = run_correlations([only_step], history, seen)

    if result != []:
        raise AssertionError(f"expected no correlation with a missing precursor, got {result}")


def test_dedup_on_replayed_event():
    history = EventHistory()
    seen = set()

    first = _finding_at(FIREWALL_RULE_DELETED, "erin@example.com", "2026-01-01T00:00:00Z")
    second = _finding_at(VM_INSTANCE_DELETED, "erin@example.com", "2026-01-01T00:05:00Z")

    run_correlations([first], history, seen)
    first_result = run_correlations([second], history, seen)
    # Same trigger event replayed (e.g. a Pub/Sub redelivery) -- must
    # not produce a second correlated finding for evidence already
    # fingerprinted and seen.
    replayed_result = run_correlations([second], history, seen)

    if len(first_result) != 1:
        raise AssertionError(f"expected exactly 1 correlation on first delivery, got {len(first_result)}")
    if replayed_result != []:
        raise AssertionError(f"expected no correlation on replay, got {replayed_result}")


TESTS = [
    ("Privilege escalation correlation fires", test_privilege_escalation_correlation_fires),
    ("Firewall removal before VM destruction fires", test_firewall_removal_before_vm_destruction_fires),
    ("Different actors do not correlate", test_different_actors_do_not_correlate),
    ("Outside time window does not correlate", test_outside_time_window_does_not_correlate),
    ("Missing precursor does not correlate", test_missing_precursor_does_not_correlate),
    ("Dedup on replayed event", test_dedup_on_replayed_event),
]


def main():
    print("\nRunning correlation tests...\n")

    results = []
    for label, test_fn in TESTS:
        try:
            test_fn()
            results.append((label, True, None))
        except AssertionError as e:
            results.append((label, False, str(e)))
        except Exception as e:  # noqa: BLE001 - surface any unexpected error as a framework problem
            raise TestFrameworkError(f"{label}: unexpected error: {e}") from e

    for label, passed, error in results:
        status = "PASSED" if passed else "FAILED"
        mark = "\u2713" if passed else "\u2717"
        dots = "." * max(3, 40 - len(label))
        print(f"{mark} {label} {dots} {status}")
        if not passed:
            print(f"    {error}")

    total = len(results)
    passed_count = sum(1 for r in results if r[1])
    print(f"\n{passed_count}/{total} tests passed")

    sys.exit(0 if passed_count == total else 1)


if __name__ == "__main__":
    try:
        main()
    except TestFrameworkError as e:
        print(f"FRAMEWORK ERROR: {e}")
        sys.exit(2)
