"""
Detection engine regression test runner.

Independent of Flask, GCP, Pub/Sub, and OpenSearch — imports only
detector.py and exercises run_detections() directly against fixture
events.

Usage:
    python tests/test_runner.py
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _locate_detector_dir():
    """
    Find the directory containing detector.py by searching the repo,
    rather than hardcoding a folder name that drifts every time the
    project gets reorganized. Searches PROJECT_ROOT itself first
    (covers the case where tests/ sits directly next to detector.py),
    then falls back to a recursive search (covers detector.py living
    inside a subfolder, whatever it's named).

    Fails loudly and immediately if detector.py can't be found or if
    more than one copy exists — an ambiguous import is worse than no
    import.
    """
    if (PROJECT_ROOT / "detector.py").exists():
        return PROJECT_ROOT

    matches = list(PROJECT_ROOT.rglob("detector.py"))
    # Ignore anything under tests/, hidden directories (.venv, .cache,
    # .git, ...), and installed-package locations — only project
    # source should be considered a candidate.
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
        print(f"FRAMEWORK ERROR: could not find detector.py anywhere under {PROJECT_ROOT}")
        sys.exit(2)
    print(f"FRAMEWORK ERROR: found multiple detector.py files, ambiguous which to import:")
    for m in matches:
        print(f"    {m}")
    sys.exit(2)


sys.path.insert(0, str(_locate_detector_dir()))

from detector import run_detections  # noqa: E402

TESTS_DIR = Path(__file__).resolve().parent
TEST_CASES_DIR = TESTS_DIR / "test_cases"
EXPECTED_RESULTS_PATH = TESTS_DIR / "expected_results.json"

# The fields a finding is judged on. Extend this tuple (e.g. add
# "confidence", "tactic", "rule_id") as run_detections()'s finding
# model grows — nothing else in this file needs to change.
COMPARISON_KEYS = ("rule_name", "mitre_technique", "severity")


class TestFrameworkError(Exception):
    """Raised for problems with the test setup itself, not the
    detection engine — bad JSON, missing files, malformed
    expectations. Kept distinct from a failing test so the two
    failure modes are never confused in the output."""


def load_expected_results():
    if not EXPECTED_RESULTS_PATH.exists():
        raise TestFrameworkError(
            f"expected_results.json not found at {EXPECTED_RESULTS_PATH}"
        )
    try:
        with open(EXPECTED_RESULTS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise TestFrameworkError(f"expected_results.json is not valid JSON: {e}")


def discover_fixture_files():
    if not TEST_CASES_DIR.exists():
        raise TestFrameworkError(f"test_cases/ directory not found at {TEST_CASES_DIR}")
    return {p.name for p in TEST_CASES_DIR.glob("*.json")}


def reconcile_fixtures_and_expectations(fixture_files, expected_results):
    """
    Cross-check discovery: fixtures with no expectation are a silent
    testing gap; expectations with no fixture are dead config (stale
    rename, deleted file, typo). Both get a loud warning — neither
    should fail silently.
    """
    expected_keys = set(expected_results.keys())

    orphan_fixtures = fixture_files - expected_keys
    orphan_expectations = expected_keys - fixture_files

    for name in sorted(orphan_fixtures):
        print(f"WARNING: {name} exists in test_cases/ but has no entry "
              f"in expected_results.json — this test will NOT run.")
    for name in sorted(orphan_expectations):
        print(f"WARNING: expected_results.json has an entry for {name} "
              f"but no matching file exists in test_cases/ — skipping.")

    # Only run tests that have both a fixture and an expectation.
    return sorted(fixture_files & expected_keys)


def validate_expectation_shape(test_case_filename, expected):
    """Fail early with a clear message if the expectation entry itself
    is malformed, rather than letting a cryptic KeyError/TypeError
    surface later during comparison."""
    if "expected_findings" not in expected:
        raise TestFrameworkError(
            f"{test_case_filename}: expected_results.json entry is missing "
            f"'expected_findings'"
        )
    if not isinstance(expected["expected_findings"], list):
        raise TestFrameworkError(
            f"{test_case_filename}: 'expected_findings' must be a list, "
            f"got {type(expected['expected_findings']).__name__}"
        )


def load_event(test_case_filename):
    path = TEST_CASES_DIR / test_case_filename
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise TestFrameworkError(f"{test_case_filename} is not valid JSON: {e}")


def normalize_findings(findings):
    """Reduce findings to the comparable keys and sort by rule_name so
    ordering differences in the engine's internal rule list never
    cause a false failure."""
    reduced = [
        {key: finding.get(key) for key in COMPARISON_KEYS}
        for finding in findings
    ]
    return sorted(reduced, key=lambda f: f["rule_name"] or "")


def diff_findings(expected_reduced, actual_reduced):
    """Return (missing, unexpected) — findings expected but absent,
    and findings present but not expected. Using rule_name as the
    dedup key since that's the natural identity of a finding today.
    (If rules ever gain a stable rule_id independent of their display
    name, switch the dedup key to that instead.)"""
    expected_by_name = {f["rule_name"]: f for f in expected_reduced}
    actual_by_name = {f["rule_name"]: f for f in actual_reduced}

    missing_names = set(expected_by_name) - set(actual_by_name)
    unexpected_names = set(actual_by_name) - set(expected_by_name)

    missing = [expected_by_name[n] for n in missing_names]
    unexpected = [actual_by_name[n] for n in unexpected_names]
    return missing, unexpected


def run_single_test(test_case_filename, expected):
    validate_expectation_shape(test_case_filename, expected)
    event = load_event(test_case_filename)
    actual_findings = run_detections(event)

    actual_reduced = normalize_findings(actual_findings)
    expected_reduced = normalize_findings(expected["expected_findings"])

    passed = actual_reduced == expected_reduced
    missing, unexpected = ([], []) if passed else diff_findings(
        expected_reduced, actual_reduced
    )
    # actual_count comes straight from actual_reduced — never
    # reconstructed from missing/unexpected, so it stays correct even
    # if diff_findings()'s logic changes later.
    return passed, missing, unexpected, len(actual_reduced)


def main():
    try:
        expected_results = load_expected_results()
        fixture_files = discover_fixture_files()
    except TestFrameworkError as e:
        print(f"FRAMEWORK ERROR: {e}")
        sys.exit(2)

    runnable = reconcile_fixtures_and_expectations(fixture_files, expected_results)

    print("\nRunning detection tests...\n")

    results = []
    for test_case_filename in runnable:
        expected = expected_results[test_case_filename]
        try:
            passed, missing, unexpected, actual_count = run_single_test(
                test_case_filename, expected
            )
        except TestFrameworkError as e:
            print(f"FRAMEWORK ERROR in {test_case_filename}: {e}")
            sys.exit(2)
        results.append(
            (test_case_filename, passed, missing, unexpected, actual_count, expected)
        )

    for test_case_filename, passed, missing, unexpected, actual_count, expected in results:
        label = expected.get("description", test_case_filename)
        status = "PASSED" if passed else "FAILED"
        mark = "\u2713" if passed else "\u2717"
        dots = "." * max(3, 40 - len(label))
        print(f"{mark} {label} {dots} {status}")

        if not passed:
            expected_count = len(expected["expected_findings"])
            print(f"    expected {expected_count} finding(s), got {actual_count}")
            for f in missing:
                print(f"    MISSING:    {f['rule_name']} ({f['mitre_technique']}, {f['severity']})")
            for f in unexpected:
                print(f"    UNEXPECTED: {f['rule_name']} ({f['mitre_technique']}, {f['severity']})")

    total = len(results)
    passed_count = sum(1 for r in results if r[1])
    print(f"\n{passed_count}/{total} tests passed")

    sys.exit(0 if passed_count == total else 1)


if __name__ == "__main__":
    main()
