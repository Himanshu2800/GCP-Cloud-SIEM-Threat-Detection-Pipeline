
import base64
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from normalizer import normalize_event  # noqa: E402
from enrichment import enrich_event  # noqa: E402
from detector import run_detections  # noqa: E402
from rule_loader import load_rules  # noqa: E402

SAMPLE = json.loads((ROOT.parent / "docs" / "sample-vpc-flow-log.json").read_text())
AUDIT = json.loads((ROOT.parent / "docs" / "sample-delete-vm-log.json").read_text())
RULES = load_rules()
RULE_ID = "GCP_LARGE_EGRESS_PUBLIC_IP"


def envelope(log):
    data = base64.b64encode(json.dumps(log).encode()).decode()
    return {"message": {"data": data}}


def pipeline(log):
    enriched = enrich_event(normalize_event(envelope(log)))
    return enriched, run_detections(enriched, RULES)


def variant(**changes):
    log = copy.deepcopy(SAMPLE)
    payload = log["jsonPayload"]
    for key, value in changes.items():
        if key == "dest_ip":
            payload["connection"]["dest_ip"] = value
        else:
            payload[key] = value
    return log


def t_rule_loaded():
    return RULE_ID in {r["rule_id"] for r in RULES}


def t_normalized_fields():
    ev, _ = pipeline(SAMPLE)
    return (ev["action"] == "vpc_flow" and ev["actor"] == "opensearch-vm"
            and ev["source_ip"] == "10.0.0.5" and ev["dest_ip"] == "198.51.100.23"
            and ev["dest_port"] == 443 and ev["bytes_sent"] == 157286400
            and ev["reporter"] == "SRC")


def t_enrichment():
    ev, _ = pipeline(SAMPLE)
    return (ev["dest_ip_classification"] == "public" and ev["ip_classification"] == "private"
            and ev["event_category"] == "Network Flow")


def t_large_public_egress_fires():
    _, hits = pipeline(SAMPLE)
    return [h["rule_id"] for h in hits] == [RULE_ID] and hits[0]["mitre_technique"] == "T1048"


def t_small_transfer_silent():
    return pipeline(variant(bytes_sent="1024"))[1] == []


def t_private_destination_silent():
    return pipeline(variant(dest_ip="10.0.0.9"))[1] == []


def t_dest_reporter_silent():
    return pipeline(variant(reporter="DEST"))[1] == []


def t_bad_bytes_value_is_safe():
    ev, hits = pipeline(variant(bytes_sent="not-a-number"))
    return ev["bytes_sent"] == 0 and hits == []


def t_audit_logs_unchanged():
    ev, _ = pipeline(AUDIT)
    return ev["action"] != "vpc_flow" and "dest_ip" not in ev


TESTS = [
    ("Large egress rule loads", t_rule_loaded),
    ("Flow log normalizes to flat fields", t_normalized_fields),
    ("Enrichment classifies destination IP", t_enrichment),
    ("150 MB to a public IP fires T1048", t_large_public_egress_fires),
    ("1 KB to a public IP stays silent", t_small_transfer_silent),
    ("Large transfer to a private IP stays silent", t_private_destination_silent),
    ("DEST-side duplicate record stays silent", t_dest_reporter_silent),
    ("Non-numeric bytes_sent is safe", t_bad_bytes_value_is_safe),
    ("Audit log path is unchanged", t_audit_logs_unchanged),
]


def main():
    print("\nRunning VPC flow log tests...\n")
    passed = 0

    for label, fn in TESTS:
        try:
            ok = bool(fn())
        except Exception as exc:
            ok = False
            print(f"    exception: {exc!r}")

        passed += ok
        dots = "." * max(3, 48 - len(label))

        symbol = "\u2713" if ok else "\u2717"
        status = "PASSED" if ok else "FAILED"

        print(f"{symbol} {label} {dots} {status}")

    print(f"\n{passed}/{len(TESTS)} tests passed")
    sys.exit(0 if passed == len(TESTS) else 1)


if __name__ == "__main__":
    main()
