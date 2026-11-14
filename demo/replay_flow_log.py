import base64
import copy
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "cloud-functions"))
import main  
SAMPLE = json.loads((ROOT / "docs" / "sample-vpc-flow-log.json").read_text())
RESULTS = []
def fake_index(document, doc_type="raw_event"):
    RESULTS.append(("index", doc_type, document))
def fake_route(finding, normalized):
    RESULTS.append(("alert", finding.get("severity"), finding))

main.index_document = fake_index
main.route_alert = fake_route

def send(label, log):
    RESULTS.clear()
    body = {"message": {"data": base64.b64encode(json.dumps(log).encode()).decode()}}
    status = main.app.test_client().post("/", json=body).status_code
    print(f"\n=== {label} ===")
    print(f"HTTP {status}")
    for kind, tag, doc in RESULTS:
        if kind == "index" and tag == "raw_event":
            print(f"  indexed raw_event: actor={doc['actor']} dest={doc['dest_ip']} "
                  f"({doc['dest_ip_classification']}) bytes={doc['bytes_sent']:,}")
        elif kind == "index":
            print(f"  indexed {tag}: {doc['rule_id']} ({doc['mitre_technique']})")
        else:
            print(f"  ALERT -> Slack + PagerDuty route, severity {tag}: {doc['rule_name']}")
    if not any(k == "alert" for k, _, _ in RESULTS):
        print("  no alert")
def variant(**changes):
    log = copy.deepcopy(SAMPLE)
    for key, value in changes.items():
        if key == "dest_ip":
            log["jsonPayload"]["connection"]["dest_ip"] = value
        else:
            log["jsonPayload"][key] = value
    return log
if __name__ == "__main__":
    send("150 MB to a public IP (should alert)", SAMPLE)
    send("1 KB to a public IP (benign)", variant(bytes_sent="1024"))
    send("150 MB to a private IP (internal, benign)", variant(dest_ip="10.0.0.9"))
    send("150 MB, DEST-side duplicate record (benign)", variant(reporter="DEST"))
